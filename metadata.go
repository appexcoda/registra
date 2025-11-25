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
	case ".pdf":
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
	case ".gp", ".gpx", ".pdf":
		return true
	}
	return false
}
