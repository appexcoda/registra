package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	logLevel := getEnv("LOG_LEVEL", "info")
	InitLogger(logLevel)

	filesPathStr := getEnv("FILES_PATH", "")
	if filesPathStr == "" {
		AppLogger.Error("FILES_PATH must be specified")
		os.Exit(1)
	}

	filesPaths := strings.FieldsFunc(filesPathStr, func(r rune) bool {
		return r == ',' || r == ';'
	})

	var validPaths []string
	for _, path := range filesPaths {
		path = strings.TrimSpace(path)
		if path != "" {
			validPaths = append(validPaths, path)
		}
	}

	if len(validPaths) == 0 {
		AppLogger.Error("FILES_PATH contains no valid directories")
		os.Exit(1)
	}

	uploadPathGP := strings.TrimSpace(getEnv("UPLOAD_PATH_GP", ""))
	uploadPathPDF := strings.TrimSpace(getEnv("UPLOAD_PATH_PDF", ""))
	uploadPathMSCZ := strings.TrimSpace(getEnv("UPLOAD_PATH_MSCZ", ""))
	uploadPathMXML := strings.TrimSpace(getEnv("UPLOAD_PATH_MXML", ""))

	if uploadPathGP == "" {
		AppLogger.Error("UPLOAD_PATH_GP must be specified")
		os.Exit(1)
	}

	if uploadPathPDF == "" {
		AppLogger.Error("UPLOAD_PATH_PDF must be specified")
		os.Exit(1)
	}

	if uploadPathMSCZ == "" {
		AppLogger.Error("UPLOAD_PATH_MSCZ must be specified")
		os.Exit(1)
	}

	if uploadPathMXML == "" {
		AppLogger.Error("UPLOAD_PATH_MXML must be specified")
		os.Exit(1)
	}

	dbPath := getEnv("DB_PATH", "")
	if dbPath == "" {
		AppLogger.Error("DB_PATH must be specified")
		os.Exit(1)
	}

	certsPath := getEnv("CERTS_PATH", "")
	if certsPath == "" {
		AppLogger.Error("CERTS_PATH must be specified")
		os.Exit(1)
	}

	port := getEnv("PORT", "8443")

	if err := validateUploadPaths(uploadPathGP, uploadPathPDF, uploadPathMSCZ, uploadPathMXML, validPaths); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	AppLogger.Info("Registra starting...")
	AppLogger.Info("Indexed directories: %v", validPaths)
	AppLogger.Info("Upload directory (GP/GPX): %s", uploadPathGP)
	AppLogger.Info("Upload directory (PDF): %s", uploadPathPDF)
	AppLogger.Info("Upload directory (MSCZ): %s", uploadPathMSCZ)
	AppLogger.Info("Upload directory (MXML): %s", uploadPathMXML)
	AppLogger.Info("Database: %s", dbPath)
	AppLogger.Info("Certificates: %s", certsPath)

	for _, path := range validPaths {
		if err := validateDirectory(path, "FILES_PATH"); err != nil {
			AppLogger.Error("%v", err)
			os.Exit(1)
		}
	}

	if err := validateWritableDirectory(uploadPathGP, "UPLOAD_PATH_GP"); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	if err := validateWritableDirectory(uploadPathPDF, "UPLOAD_PATH_PDF"); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	if err := validateWritableDirectory(uploadPathMSCZ, "UPLOAD_PATH_MSCZ"); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	if err := validateWritableDirectory(uploadPathMXML, "UPLOAD_PATH_MXML"); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	if err := ensureWritableDirectory(certsPath, "CERTS_PATH"); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	dbDir := filepath.Dir(dbPath)
	if err := ensureWritableDirectory(dbDir, "DB_PATH parent directory"); err != nil {
		AppLogger.Error("%v", err)
		os.Exit(1)
	}

	uploadPaths := []string{uploadPathGP, uploadPathPDF, uploadPathMSCZ, uploadPathMXML}
	uploadPathsSet := make(map[string]bool)

	for _, uploadPath := range uploadPaths {
		if uploadPathsSet[uploadPath] {
			continue
		}
		uploadPathsSet[uploadPath] = true

		absUploadPath, err := filepath.Abs(uploadPath)
		if err != nil {
			AppLogger.Error("Invalid upload path: %v", err)
			os.Exit(1)
		}

		uploadPathInList := false
		for _, p := range validPaths {
			absPath, err := filepath.Abs(p)
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(absPath, absUploadPath)
			if err == nil && (rel == "." || !strings.HasPrefix(rel, "..")) {
				uploadPathInList = true
				break
			}
		}

		if !uploadPathInList {
			AppLogger.Info("Adding upload directory to indexed paths: %s", uploadPath)
			validPaths = append(validPaths, uploadPath)
		}
	}

	auth, err := NewAuth(certsPath)
	if err != nil {
		AppLogger.Error("Failed to initialize auth: %v", err)
		os.Exit(1)
	}

	mainIP := GetOutboundIP()
	AppLogger.Info("Main network IP: %s", mainIP)

	certPath, keyPath, err := EnsureCertificates(certsPath, mainIP)
	if err != nil {
		AppLogger.Error("Failed to setup SSL certificates: %v", err)
		os.Exit(1)
	}

	db, err := NewDB(dbPath)
	if err != nil {
		AppLogger.Error("Failed to initialize database: %v", err)
		os.Exit(1)
	}

	indexer := NewIndexer(db, validPaths, 10)

	AppLogger.Info("Running initial scan...")
	if err := indexer.InitialScan(); err != nil {
		AppLogger.Error("Initial scan error: %v", err)
	}

	AppLogger.Info("Starting periodic scanner (scans every %v)", time.Minute)
	indexer.StartPeriodicScan()

	mscorePath := getEnv("MSCORE", "")
	handlers := NewHandlers(db, indexer, uploadPathGP, uploadPathPDF, uploadPathMSCZ, uploadPathMXML, mscorePath)

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(RequestIDMiddleware)
	r.Use(LoggingMiddleware)
	r.Use(handlers.RateLimitMiddleware)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Get("/health", handlers.Health)
		r.Get("/stats", handlers.Stats)
		r.Get("/search", handlers.Search)
		r.Get("/files/{id}", handlers.Download)
		r.Get("/files/{id}/preview", handlers.Preview)
		r.Post("/files", handlers.Upload)
		r.Delete("/files/{id}", handlers.Delete)
		r.Post("/scan", handlers.TriggerScan)
		r.Post("/mscz", handlers.ConvertMSCZ)
	})

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := GenerateConnectionQR(mainIP, auth.GetKey(), port); err != nil {
		AppLogger.Warn("Failed to generate QR code: %v", err)
	}

	AppLogger.Info("Starting HTTPS server on https://%s:%s", mainIP, port)
	AppLogger.Error("Server error: %v", server.ListenAndServeTLS(certPath, keyPath))
}

func validateUploadPaths(uploadGP, uploadPDF, uploadMSCZ, uploadMXML string, filesPaths []string) error {
	absUploadGP, err := filepath.Abs(uploadGP)
	if err != nil {
		return fmt.Errorf("invalid UPLOAD_PATH_GP: %v", err)
	}

	absUploadPDF, err := filepath.Abs(uploadPDF)
	if err != nil {
		return fmt.Errorf("invalid UPLOAD_PATH_PDF: %v", err)
	}

	absUploadMSCZ, err := filepath.Abs(uploadMSCZ)
	if err != nil {
		return fmt.Errorf("invalid UPLOAD_PATH_MSCZ: %v", err)
	}

	absUploadMXML, err := filepath.Abs(uploadMXML)
	if err != nil {
		return fmt.Errorf("invalid UPLOAD_PATH_MXML: %v", err)
	}

	if absUploadGP == absUploadPDF {
		return fmt.Errorf("UPLOAD_PATH_GP and UPLOAD_PATH_PDF cannot be the same directory: %s", absUploadGP)
	}

	if absUploadGP == absUploadMSCZ {
		return fmt.Errorf("UPLOAD_PATH_GP and UPLOAD_PATH_MSCZ cannot be the same directory: %s", absUploadGP)
	}

	if absUploadGP == absUploadMXML {
		return fmt.Errorf("UPLOAD_PATH_GP and UPLOAD_PATH_MXML cannot be the same directory: %s", absUploadGP)
	}

	if absUploadPDF == absUploadMSCZ {
		return fmt.Errorf("UPLOAD_PATH_PDF and UPLOAD_PATH_MSCZ cannot be the same directory: %s", absUploadPDF)
	}

	if absUploadPDF == absUploadMXML {
		return fmt.Errorf("UPLOAD_PATH_PDF and UPLOAD_PATH_MXML cannot be the same directory: %s", absUploadPDF)
	}

	if absUploadMSCZ == absUploadMXML {
		return fmt.Errorf("UPLOAD_PATH_MSCZ and UPLOAD_PATH_MXML cannot be the same directory: %s", absUploadMSCZ)
	}

	for _, filesPath := range filesPaths {
		absFilesPath, err := filepath.Abs(filesPath)
		if err != nil {
			continue
		}

		if absUploadGP == absFilesPath {
			return fmt.Errorf("UPLOAD_PATH_GP cannot be the same as FILES_PATH: %s", absUploadGP)
		}

		if absUploadPDF == absFilesPath {
			return fmt.Errorf("UPLOAD_PATH_PDF cannot be the same as FILES_PATH: %s", absUploadPDF)
		}

		if absUploadMSCZ == absFilesPath {
			return fmt.Errorf("UPLOAD_PATH_MSCZ cannot be the same as FILES_PATH: %s", absUploadMSCZ)
		}

		if absUploadMXML == absFilesPath {
			return fmt.Errorf("UPLOAD_PATH_MXML cannot be the same as FILES_PATH: %s", absUploadMXML)
		}
	}

	return nil
}

func validateDirectory(path, label string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("%s directory does not exist: %s", label, path)
	}
	if err != nil {
		return fmt.Errorf("error accessing %s directory %s: %v", label, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory: %s", label, path)
	}
	return nil
}

func validateWritableDirectory(path, label string) error {
	if err := validateDirectory(path, label); err != nil {
		return err
	}

	testFile := filepath.Join(path, ".write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("%s directory %s is not writable: %v", label, path, err)
	}
	os.Remove(testFile)

	AppLogger.Info("%s directory verified: %s", label, path)
	return nil
}

func ensureWritableDirectory(path, label string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory %s: %v", label, path, err)
	}

	testFile := filepath.Join(path, ".write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("%s directory %s is not writable: %v", label, path, err)
	}
	os.Remove(testFile)

	AppLogger.Info("%s directory verified: %s", label, path)
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
