package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Auth struct {
	apiKey string
}

func NewAuth(certsDir string) (*Auth, error) {
	var apiKey string

	envKey := os.Getenv("API_KEY")
	if envKey != "" {
		apiKey = envKey
		return &Auth{apiKey: apiKey}, nil
	}

	keyFilePath := filepath.Join(certsDir, "api_key.txt")
	fileKey, err := os.ReadFile(keyFilePath)
	if err == nil {
		apiKey = strings.TrimSpace(string(fileKey))
		return &Auth{apiKey: apiKey}, nil
	}

	apiKey, err = generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %v", err)
	}

	if err := os.WriteFile(keyFilePath, []byte(apiKey), 0600); err != nil {
		return nil, fmt.Errorf("failed to save API key: %v", err)
	}

	return &Auth{apiKey: apiKey}, nil
}

func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (a *Auth) GetKey() string {
	return a.apiKey
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		apiKeyHeader := r.Header.Get("X-API-Key")

		var providedKey string
		if strings.HasPrefix(authHeader, "Bearer ") {
			providedKey = strings.TrimPrefix(authHeader, "Bearer ")
		} else if apiKeyHeader != "" {
			providedKey = apiKeyHeader
		}

		if !constantTimeCompareKeys(providedKey, a.apiKey) {
			respondError(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func constantTimeCompareKeys(provided, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
