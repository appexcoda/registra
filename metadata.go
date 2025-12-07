package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type FileMetadata struct {
	ID         int64
	FilePath   string
	FileName   string
	FileType   string
	Artist     string
	Title      string
	SubTitle   string
	Album      string
	FileHash   string
	FileSize   int64
	IndexedAt  time.Time
	ModifiedAt time.Time
	IsUploaded bool `json:"IsUploaded,omitempty"`
}

type GPIF struct {
	Score GPScore `xml:"Score"`
}

type GPScore struct {
	Title    string `xml:"Title"`
	SubTitle string `xml:"SubTitle"`
	Artist   string `xml:"Artist"`
	Album    string `xml:"Album"`
}

// MusicXML structures for metadata extraction
type MusicXMLScore struct {
	Work      MusicXMLWork       `xml:"work"`
	Creators  []MusicXMLCreator  `xml:"identification>creator"`
	Credits   []MusicXMLCredit   `xml:"credit"`
	Movements []MusicXMLMovement `xml:"movement-title"`
}

type MusicXMLWork struct {
	WorkTitle string `xml:"work-title"`
}

type MusicXMLCreator struct {
	Type string `xml:"type,attr"`
	Name string `xml:",chardata"`
}

type MusicXMLCredit struct {
	Page        int                   `xml:"page,attr"`
	CreditType  string                `xml:"credit-type"`
	CreditWords []MusicXMLCreditWords `xml:"credit-words"`
}

type MusicXMLCreditWords struct {
	Content string `xml:",chardata"`
}

type MusicXMLMovement struct {
	Title string `xml:",chardata"`
}

func ExtractMetadata(filePath string) (*FileMetadata, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	metadata := &FileMetadata{
		FilePath:   filePath,
		FileName:   filepath.Base(filePath),
		FileType:   strings.TrimPrefix(ext, "."),
		FileSize:   info.Size(),
		ModifiedAt: info.ModTime(),
		IndexedAt:  time.Now(),
	}

	switch ext {
	case ".gp":
		if err := extractGuitarProZipMetadata(filePath, metadata); err != nil {
			return nil, fmt.Errorf("invalid GP file (missing or corrupt score.gpif): %w", err)
		}
	case ".gpx":
		if err := extractGuitarProGpxMetadata(filePath, metadata); err != nil {
			return nil, fmt.Errorf("invalid GPX file (missing or corrupt score.gpif): %w", err)
		}
	case ".musicxml":
		if err := extractMusicXMLMetadata(filePath, metadata); err != nil {
			return nil, fmt.Errorf("invalid MusicXML file: %w", err)
		}
	case ".pdf", ".mscz":
		metadata.Title = strings.TrimSuffix(metadata.FileName, ext)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}

	hash, err := calculateFileHash(filePath)
	if err == nil {
		metadata.FileHash = hash
	}

	return metadata, nil
}

func extractGuitarProZipMetadata(filePath string, metadata *FileMetadata) error {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.EqualFold(filepath.Base(f.Name), "score.gpif") {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			return parseScoreGpif(rc, metadata)
		}
	}

	return fmt.Errorf("score.gpif not found in ZIP")
}

func extractGuitarProGpxMetadata(filePath string, metadata *FileMetadata) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fs := NewGpxFileSystem()
	if err := fs.Load(file); err != nil {
		return err
	}

	for _, f := range fs.Files {
		if strings.EqualFold(f.FileName, "score.gpif") {
			reader := bytes.NewReader(f.Data)
			return parseScoreGpif(reader, metadata)
		}
	}

	return fmt.Errorf("score.gpif not found in GPX")
}

func parseScoreGpif(reader io.Reader, metadata *FileMetadata) error {
	var gpif GPIF
	if err := xml.NewDecoder(reader).Decode(&gpif); err != nil {
		return err
	}

	metadata.Title = strings.TrimSpace(gpif.Score.Title)
	metadata.SubTitle = strings.TrimSpace(gpif.Score.SubTitle)
	metadata.Artist = strings.TrimSpace(gpif.Score.Artist)
	metadata.Album = strings.TrimSpace(gpif.Score.Album)

	return nil
}

func calculateFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func isSupportedFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".gp", ".gpx", ".pdf", ".mscz", ".musicxml":
		return true
	}
	return false
}

// extractMusicXMLMetadata extracts metadata from uncompressed .musicxml files
func extractMusicXMLMetadata(filePath string, metadata *FileMetadata) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	return parseMusicXML(file, metadata)
}

// parseMusicXML parses MusicXML content and extracts metadata
func parseMusicXML(reader io.Reader, metadata *FileMetadata) error {
	fullContent, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Detect UTF-16 encoding by checking BOM or looking for null bytes
	var decodedReader io.Reader
	isUTF16 := false

	if len(fullContent) >= 2 {
		if (fullContent[0] == 0xFF && fullContent[1] == 0xFE) ||
			(fullContent[0] == 0xFE && fullContent[1] == 0xFF) {
			isUTF16 = true
		} else if len(fullContent) >= 4 {
			if (fullContent[1] == 0x00 && fullContent[3] == 0x00) ||
				(fullContent[0] == 0x00 && fullContent[2] == 0x00) {
				isUTF16 = true
			}
		}
	}

	if isUTF16 {
		utf16Decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
		decodedReader = transform.NewReader(bytes.NewReader(fullContent), utf16Decoder)
	} else {
		decodedReader = bytes.NewReader(fullContent)
	}

	decoder := xml.NewDecoder(decodedReader)
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "UTF-16") || strings.EqualFold(charset, "UTF-16LE") || strings.EqualFold(charset, "UTF-16BE") {
			return input, nil
		}
		return input, nil
	}

	var score MusicXMLScore
	if err := decoder.Decode(&score); err != nil {
		return err
	}

	for _, creator := range score.Creators {
		if creator.Type == "composer" {
			metadata.Artist = strings.TrimSpace(creator.Name)
			break
		}
	}

	if score.Work.WorkTitle != "" {
		metadata.Title = strings.TrimSpace(score.Work.WorkTitle)
	} else if len(score.Movements) > 0 {
		metadata.Title = strings.TrimSpace(score.Movements[0].Title)
	}

	for _, credit := range score.Credits {
		if credit.Page == 1 {
			if metadata.Title == "" && credit.CreditType == "title" {
				for _, cw := range credit.CreditWords {
					content := strings.TrimSpace(cw.Content)
					if content != "" {
						metadata.Title = content
						break
					}
				}
			}

			if credit.CreditType == "subtitle" {
				for i, cw := range credit.CreditWords {
					content := strings.TrimSpace(cw.Content)
					if content != "" {
						isURL := strings.Contains(content, "www.") || strings.Contains(content, "http")

						if i == 0 && metadata.SubTitle == "" {
							metadata.SubTitle = content
						}

						if i > 0 && metadata.Artist == "" && !isURL {
							metadata.Artist = content
						}
					}
				}
			}
		}
	}

	return nil
}
