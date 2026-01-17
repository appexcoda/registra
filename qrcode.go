package main

import (
	"encoding/json"
	"fmt"

	"github.com/skip2/go-qrcode"
)

type QRPayload struct {
	URL string `json:"url"`
	Key string `json:"key"`
	V   int    `json:"v"`
}

func GenerateConnectionQR(ip string, apiKey string, port string) error {
	url := fmt.Sprintf("https://%s:%s", ip, port)

	payload := QRPayload{
		URL: url,
		Key: apiKey,
		V:   1,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal QR payload: %v", err)
	}

	qr, err := qrcode.New(string(jsonData), qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %v", err)
	}

	fmt.Println()
	fmt.Println("CONNECTION QR CODE")
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("║ URL: %s\n", url)
	fmt.Printf("║ Key: %s\n", apiKey)
	fmt.Println("║")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	return nil
}
