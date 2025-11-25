package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

const (
	maxUploadSize      = 100 << 20 
	rateLimitPerSecond = 100
	rateLimitBurst     = 10
	tempHashBytes      = 16 
)

var (
	ErrDuplicateFile = errors.New("Duplicate file")
	ErrFileNotFound  = errors.New("File not found")
)

type Handlers struct {
	db            *DB
	indexer       *Indexer
	uploadPathGP  string 
	uploadPathPDF string
	limiter       *RateLimiter
}

func NewHandlers(db *DB, indexer *Indexer, uploadPathGP, uploadPathPDF string) *Handlers {
	return &Handlers{
		db:            db,
		indexer:       indexer,
		uploadPathGP:  uploadPathGP,
		uploadPathPDF: uploadPathPDF,
		limiter:       NewRateLimiter(rateLimitPerSecond, rateLimitBurst),
	}
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limiter, exists := rl.limiters[ip]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters[ip] = limiter
	return limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}

func (h *Handlers) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !h.limiter.Allow(ip) {
			respondError(w, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

func (h *Handlers) Search(w http.ResponseWriter, r *http.Request) {
	requestID := GetRequestID(r)

	text := strings.TrimSpace(r.URL.Query().Get("text"))
	artist := strings.TrimSpace(r.URL.Query().Get("artist"))
	title := strings.TrimSpace(r.URL.Query().Get("title"))

	if text == "" && artist == "" && title == "" {
		respondError(w, http.StatusBadRequest, "at least one search parameter required: 'text', 'artist', or 'title'")
		return
	}

	page := 1
	pageSize := 20

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 {
			pageSize = ps
			if pageSize > 100 {
				pageSize = 100
			}
		}
	}

	fileType := r.URL.Query().Get("file_type")
	if fileType != "" {
		fileType = strings.ToLower(fileType)
		if fileType != "pdf" && fileType != "gp" {
			respondError(w, http.StatusBadRequest, "invalid file_type: must be 'pdf' or 'gp'")
			return
		}
	}

	result, err := h.db.Search(text, page, pageSize, fileType, artist, title)
	if err != nil {
		AppLogger.ErrorWithID(requestID, "Search error: %v", err)

		errMsg := err.Error()
		if strings.Contains(errMsg, "fts5:") || strings.Contains(errMsg, "syntax error") {
			respondError(w, http.StatusBadRequest,
				"invalid search syntax - try removing special characters like @, ^, *, or quotes")
			return
		}

		respondError(w, http.StatusInternalServerError, "search failed")
		return
	}

	returned := len(result.Results)

	logParts := []string{fmt.Sprintf("Search page=%d pageSize=%d returned=%d totalResults=%d",
		page, pageSize, returned, result.Total)}
	if text != "" {
		logParts = append(logParts, fmt.Sprintf("text='%s'", text))
	}
	if artist != "" {
		logParts = append(logParts, fmt.Sprintf("artist='%s'", artist))
	}
	if title != "" {
		logParts = append(logParts, fmt.Sprintf("title='%s'", title))
	}
	if fileType != "" {
		logParts = append(logParts, fmt.Sprintf("fileType=%s", fileType))
	}
	AppLogger.InfoWithID(requestID, strings.Join(logParts, " "))

	for _, file := range result.Results {
		file.IsUploaded = h.isInUploadFolder(file.FilePath)
	}

	response := map[string]interface{}{
		"results":     result.Results,
		"total":       result.Total,
		"returned":    returned,
		"page":        result.Page,
		"page_size":   result.PageSize,
		"total_pages": result.TotalPages,
	}

	if text != "" {
		response["text"] = text
	}
	if artist != "" {
		response["artist"] = artist
	}
	if title != "" {
		response["title"] = title
	}
	if fileType != "" {
		response["file_type"] = fileType
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handlers) Upload(w http.ResponseWriter, r *http.Request) {
	requestID := GetRequestID(r)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		AppLogger.WarnWithID(requestID, "File too large")
		respondError(w, http.StatusBadRequest, "file too large")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		AppLogger.WarnWithID(requestID, "No file provided")
		respondError(w, http.StatusBadRequest, "no file provided")
		return
	}
	defer file.Close()

	if err := validateFilename(header.Filename); err != nil {
		AppLogger.WarnWithID(requestID, "Invalid filename: %s - %v", header.Filename, err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	safeFilename := filepath.Base(header.Filename)
	ext := strings.ToLower(filepath.Ext(safeFilename))

	var uploadDir string
	switch ext {
	case ".gp", ".gpx":
		uploadDir = h.uploadPathGP
	case ".pdf":
		uploadDir = h.uploadPathPDF
	default:
		AppLogger.WarnWithID(requestID, "Unsupported file type: %s", ext)
		respondError(w, http.StatusBadRequest, "Unsupported file type")
		return
	}

	destPath := filepath.Join(uploadDir, safeFilename)
	AppLogger.InfoWithID(requestID, "Upload destination: %s (type: %s)", destPath, ext)

	tempHash, err := generateRandomHex(tempHashBytes)
	if err != nil {
		AppLogger.ErrorWithID(requestID, "Failed to generate temp hash: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}

	tempFileName := fmt.Sprintf("registra-upload-%s%s", tempHash, ext)
	tempPath := filepath.Join(os.TempDir(), tempFileName)

	tempFile, err := os.Create(tempPath)
	if err != nil {
		AppLogger.ErrorWithID(requestID, "Failed to create temp file: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}

	cleanupTemp := true
	defer func() {
		tempFile.Close()
		if cleanupTemp {
			if _, err := os.Stat(tempPath); err == nil {
				os.Remove(tempPath)
			}
		}
	}()

	if _, err := io.Copy(tempFile, file); err != nil {
		AppLogger.ErrorWithID(requestID, "Failed to write temp file: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}
	tempFile.Close()

	metadata, err := ExtractMetadata(tempPath)
	if err != nil {
		AppLogger.ErrorWithID(requestID, "Failed to extract metadata: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to process file")
		return
	}

	if metadata.FileHash != "" {
		exists, existingPath, err := h.db.FileExistsByHash(metadata.FileHash)
		if err != nil {
			AppLogger.ErrorWithID(requestID, "Failed to check hash: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to check for duplicates")
			return
		}
		if exists {
			AppLogger.WarnWithID(requestID, "Upload rejected - duplicate detected: %s (identical to indexed file: %s)",
				safeFilename, existingPath)
			respondError(w, http.StatusConflict,
				fmt.Sprintf("Duplicate file: identical content already exists as '%s'", filepath.Base(existingPath)))
			return
		}
	}

	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsExist(err) {
			existingFile, dbErr := h.db.GetFileByPath(destPath)
			if dbErr != nil {
				AppLogger.WarnWithID(requestID, "File exists but not found in DB: %s", safeFilename)
				respondError(w, http.StatusConflict, "File with this name already exists")
				return
			}

			AppLogger.WarnWithID(requestID, "File already exists: %s (id=%d)", safeFilename, existingFile.ID)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "File with this name already exists",
				"existing_file": map[string]interface{}{
					"id":       existingFile.ID,
					"filename": existingFile.FileName,
				},
			})
			return
		}
		AppLogger.ErrorWithID(requestID, "Failed to create destination file: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}

	destCreated := true
	defer func() {
		destFile.Close()
		if !destCreated {
			os.Remove(destPath)
		}
	}()

	tempFileRead, err := os.Open(tempPath)
	if err != nil {
		destCreated = false
		AppLogger.ErrorWithID(requestID, "Failed to reopen temp file: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}
	defer tempFileRead.Close()

	if _, err := io.Copy(destFile, tempFileRead); err != nil {
		destCreated = false
		AppLogger.ErrorWithID(requestID, "Failed to copy to destination: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}

	tempFileRead.Close()
	destFile.Close()

	cleanupTemp = false

	if err := h.indexer.IndexFile(destPath); err != nil {
		if errors.Is(err, ErrDuplicateFile) {
			existingPath := strings.TrimPrefix(err.Error(), "duplicate file: ")
			AppLogger.InfoWithID(requestID, "Uploaded file has duplicate content: %s (identical to %s)",
				destPath, existingPath)
		} else {
			AppLogger.ErrorWithID(requestID, "Failed to index uploaded file: %v", err)
		}
	}

	AppLogger.InfoWithID(requestID, "Upload complete: %s → %s", safeFilename, uploadDir)

	go func() {
		time.Sleep(100 * time.Millisecond) 
		if err := h.indexer.InitialScan(); err != nil {
			AppLogger.ErrorWithID(requestID, "Post-upload scan failed: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "File uploaded successfully",
		"filename": safeFilename,
		"path":     uploadDir,
	})
}

func (h *Handlers) Download(w http.ResponseWriter, r *http.Request) {
	requestID := GetRequestID(r)
	id := chi.URLParam(r, "id")

	file, err := h.db.GetFileByID(id)
	if err != nil {
		AppLogger.WarnWithID(requestID, "File not found: id=%s", id)
		respondError(w, http.StatusNotFound, "File not found")
		return
	}

	if !h.indexer.IsValidPath(file.FilePath) {
		AppLogger.ErrorWithID(requestID, "Path traversal attempt: %s", file.FilePath)
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	if _, err := os.Stat(file.FilePath); os.IsNotExist(err) {
		AppLogger.WarnWithID(requestID, "File not found on disk: %s", file.FilePath)
		respondError(w, http.StatusNotFound, "File not found on disk")
		return
	}

	AppLogger.InfoWithID(requestID, "Download: id=%s file=%s", id, file.FileName)

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.FileName))
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, file.FilePath)
}

func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	requestID := GetRequestID(r)
	id := chi.URLParam(r, "id")

	file, err := h.db.GetFileByID(id)
	if err != nil {
		AppLogger.WarnWithID(requestID, "File not found for deletion: id=%s", id)
		respondError(w, http.StatusNotFound, "File not found")
		return
	}

	if !h.indexer.IsValidPath(file.FilePath) {
		AppLogger.ErrorWithID(requestID, "Path traversal attempt on delete: %s", file.FilePath)
		respondError(w, http.StatusForbidden, "Access denied")
		return
	}

	if err := os.Remove(file.FilePath); err != nil {
		AppLogger.WarnWithID(requestID, "Failed to delete file from disk: %v", err)
	}

	if err := h.db.DeleteFile(id); err != nil {
		AppLogger.ErrorWithID(requestID, "Failed to delete file from DB: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to delete file")
		return
	}

	AppLogger.InfoWithID(requestID, "File deleted: id=%s file=%s", id, file.FileName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "File deleted successfully",
	})
}

func (h *Handlers) Stats(w http.ResponseWriter, r *http.Request) {
	requestID := GetRequestID(r)

	stats, err := h.db.GetStats()
	if err != nil {
		AppLogger.ErrorWithID(requestID, "Failed to get stats: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get stats")
		return
	}

	indexerStats := h.indexer.GetMetrics()
	stats["indexer"] = indexerStats

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func validatePathWithinBase(path, base string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return fmt.Errorf("invalid base path: %w", err)
	}

	rel, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return fmt.Errorf("path not within base directory")
	}

	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("path traversal attempt detected")
	}

	return nil
}

func validateFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	if strings.ContainsAny(filename, "/\\") {
		return fmt.Errorf("filename cannot contain path separators")
	}

	if strings.HasPrefix(filename, ".") {
		return fmt.Errorf("hidden files not allowed")
	}

	for _, r := range filename {
		if r < 32 || r == 127 {
			return fmt.Errorf("filename contains invalid characters")
		}
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".gp" && ext != ".gpx" && ext != ".pdf" {
		return fmt.Errorf("Only .gp, .gpx, and .pdf files allowed")
	}

	return nil
}

func (h *Handlers) isInUploadFolder(filePath string) bool {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}

	absGP, err := filepath.Abs(h.uploadPathGP)
	if err == nil && strings.HasPrefix(absPath, absGP+string(filepath.Separator)) {
		return true
	}

	absPDF, err := filepath.Abs(h.uploadPathPDF)
	if err == nil && strings.HasPrefix(absPath, absPDF+string(filepath.Separator)) {
		return true
	}

	return false
}

func generateRandomHex(numBytes int) (string, error) {
	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (h *Handlers) TriggerScan(w http.ResponseWriter, r *http.Request) {
	requestID := GetRequestID(r)

	go func() {
		AppLogger.InfoWithID(requestID, "Manual scan triggered")
		if err := h.indexer.InitialScan(); err != nil {
			AppLogger.ErrorWithID(requestID, "Manual scan failed: %v", err)
		} else {
			AppLogger.InfoWithID(requestID, "Manual scan completed")
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Scan initiated",
	})
}
