package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

type GpxFile struct {
	FileName string
	FileSize int
	Data     []byte
}

type GpxFileSystem struct {
	Files      []*GpxFile
	FileFilter func(fileName string) bool
}

const (
	HeaderBCFS = "BCFS"
	HeaderBCFZ = "BCFZ"
	SectorSize = 0x1000
)

func NewGpxFileSystem() *GpxFileSystem {
	return &GpxFileSystem{
		Files: make([]*GpxFile, 0),
		FileFilter: func(fileName string) bool {
			return true
		},
	}
}

// Load reads the data from the reader and parses the file system.
// Note: It reads the entire stream into memory to handle the parsing.
func (gfs *GpxFileSystem) Load(r io.Reader) error {
	// We read everything into memory immediately because the format
	// requires random access semantics (jumping between sectors)
	// and look-backs during decompression.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	br := NewBitReader(data)
	return gfs.readBlock(br)
}

func (gfs *GpxFileSystem) ReadHeader(br *BitReader) (string, error) {
	data, err := br.ReadBytes(4)
	if err != nil {
		return "", err
	}
	return getString(data, 0, 4), nil
}

func (gfs *GpxFileSystem) Decompress(br *BitReader, skipHeader bool) ([]byte, error) {
	expectedLengthBytes, err := br.ReadBytes(4)
	if err != nil {
		return nil, err
	}
	expectedLength := getInteger(expectedLengthBytes, 0)

	uncompressed := make([]byte, 0, expectedLength)

	for len(uncompressed) < expectedLength {
		flag, err := br.ReadBits(1)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if flag == 1 {
			// Compressed Reference
			wordSize, err := br.ReadBits(4)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			offset, err := br.ReadBitsReversed(int(wordSize))
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			size, err := br.ReadBitsReversed(int(wordSize))
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			sourcePosition := len(uncompressed) - int(offset)
			toRead := int(math.Min(float64(offset), float64(size)))

			if sourcePosition < 0 {
				// Handle bad lookbehind with padding
				for k := 0; k < toRead; k++ {
					uncompressed = append(uncompressed, 0)
				}
				continue
			}

			for i := 0; i < toRead; i++ {
				if sourcePosition+i < len(uncompressed) {
					uncompressed = append(uncompressed, uncompressed[sourcePosition+i])
				} else {
					uncompressed = append(uncompressed, 0)
				}
			}
		} else {
			// Literal Run
			size, err := br.ReadBitsReversed(2)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			for i := 0; i < int(size); i++ {
				b, err := br.ReadByte()
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, err
				}
				uncompressed = append(uncompressed, b)
			}
		}
	}

	if skipHeader {
		if len(uncompressed) < 4 {
			return uncompressed, nil
		}
		// The standard usually has BCFS at the start of the decompressed block
		return uncompressed[4:], nil
	}
	return uncompressed, nil
}

func (gfs *GpxFileSystem) readBlock(br *BitReader) error {
	header, err := gfs.ReadHeader(br)
	if err != nil {
		return err
	}

	switch header {
	case HeaderBCFZ:
		data, err := gfs.Decompress(br, true)
		if err != nil {
			return fmt.Errorf("decompress error: %v", err)
		}
		return gfs.readUncompressedBlock(data)
	case HeaderBCFS:
		data, err := br.ReadAll()
		if err != nil {
			return err
		}
		return gfs.readUncompressedBlock(data)
	default:
		return fmt.Errorf("unsupported format: %s (expected BCFZ or BCFS)", header)
	}
}

func (gfs *GpxFileSystem) readUncompressedBlock(data []byte) error {
	offset := SectorSize

	// CRITICAL FIX: Track sectors that contain file DATA.
	// These sectors should NOT be scanned for file HEADERS.
	usedSectors := make(map[int]bool)

	for offset+3 < len(data) {
		currentSectorIdx := offset / SectorSize

		// If this sector is part of another file's data, skip it entirely
		if usedSectors[currentSectorIdx] {
			offset += SectorSize
			continue
		}

		entryType := getInteger(data, offset)

		if entryType == 2 {
			file := &GpxFile{}
			file.FileName = getString(data, offset+0x04, 127)
			file.FileSize = getInteger(data, offset+0x8c)

			// Sanity check: Empty filename usually indicates a false positive or padding
			if file.FileName == "" || file.FileSize < 0 {
				offset += SectorSize
				continue
			}

			storeFile := gfs.FileFilter == nil || gfs.FileFilter(file.FileName)
			if storeFile {
				gfs.Files = append(gfs.Files, file)
			}

			dataPointerOffset := offset + 0x94
			sectorCount := 0
			var fileData []byte

			if storeFile {
				fileData = make([]byte, 0, file.FileSize)
			}

			for {
				sectorIndex := getInteger(data, dataPointerOffset+4*sectorCount)
				sectorCount++

				if sectorIndex != 0 {
					// IMPORTANT: Mark this sector as used so we don't parse it as a header later
					usedSectors[sectorIndex] = true

					if storeFile {
						sectorOffset := sectorIndex * SectorSize
						if sectorOffset < len(data) {
							end := sectorOffset + SectorSize
							if end > len(data) {
								end = len(data)
							}
							fileData = append(fileData, data[sectorOffset:end]...)
						}
					}
				} else {
					break
				}
			}

			if storeFile && fileData != nil {
				if len(fileData) > file.FileSize {
					file.Data = fileData[:file.FileSize]
				} else {
					file.Data = fileData
				}
			}
		}

		offset += SectorSize
	}

	return nil
}

// Helpers

func getString(data []byte, offset, length int) string {
	if offset+length > len(data) {
		return ""
	}
	slice := data[offset : offset+length]
	end := 0
	for end < len(slice) {
		if slice[end] == 0 {
			break
		}
		end++
	}
	return string(slice[:end])
}

func getInteger(data []byte, offset int) int {
	if offset+4 > len(data) {
		return 0
	}
	return int(binary.LittleEndian.Uint32(data[offset : offset+4]))
}

// BitReader Implementation (Replaced with robust byte-slice version)

type BitReader struct {
	data      []byte
	byteIdx   int
	bitOffset int
}

func NewBitReader(data []byte) *BitReader {
	return &BitReader{
		data:      data,
		byteIdx:   0,
		bitOffset: 0,
	}
}

func (br *BitReader) ReadBit() (int, error) {
	if br.byteIdx >= len(br.data) {
		return 0, io.EOF
	}
	bit := (br.data[br.byteIdx] >> (7 - br.bitOffset)) & 1
	br.bitOffset++
	if br.bitOffset == 8 {
		br.bitOffset = 0
		br.byteIdx++
	}
	return int(bit), nil
}

func (br *BitReader) ReadBits(count int) (uint64, error) {
	var value uint64 = 0
	for i := 0; i < count; i++ {
		bit, err := br.ReadBit()
		if err != nil {
			return value, err
		}
		value = (value << 1) | uint64(bit)
	}
	return value, nil
}

func (br *BitReader) ReadBitsReversed(count int) (uint64, error) {
	var value uint64 = 0
	for i := 0; i < count; i++ {
		bit, err := br.ReadBit()
		if err != nil && err != io.EOF {
			return 0, err
		}
		if bit == 1 {
			value |= 1 << i
		}
	}
	return value, nil
}

func (br *BitReader) ReadByte() (byte, error) {
	val, err := br.ReadBits(8)
	return byte(val), err
}

func (br *BitReader) ReadBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		if br.bitOffset == 0 && br.byteIdx < len(br.data) {
			buf[i] = br.data[br.byteIdx]
			br.byteIdx++
		} else {
			b, err := br.ReadByte()
			if err != nil {
				return nil, err
			}
			buf[i] = b
		}
	}
	return buf, nil
}

func (br *BitReader) ReadAll() ([]byte, error) {
	if br.byteIdx >= len(br.data) {
		return []byte{}, nil
	}
	return br.data[br.byteIdx:], nil
}
