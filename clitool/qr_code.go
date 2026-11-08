package main

import (
	"fmt"
	"image/png"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

func createQrCode(data string, outFile string, size int, extract bool) error {
	var err error
	var qrCode barcode.Barcode

	if extract {
		data, err = extractTotpUrl(data)
		if err != nil {
			return err
		}
	}

	data = strings.TrimSpace(data)

	qrCode, err = qr.Encode(data, qr.M, qr.Auto)
	if err != nil {
		return err
	}

	qrCode, err = barcode.Scale(qrCode, size, size)
	if err != nil {
		return err
	}

	file, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer file.Close()

	return png.Encode(file, qrCode)
}

func startViewer(viewer string, outFile string) error {
	params := strings.Split(viewer, " ")
	sanitzedParams := []string{}

	for _, j := range params {
		if j != "" {
			sanitzedParams = append(sanitzedParams, j)
		}
	}

	sanitzedParams = append(sanitzedParams, outFile)
	cmd := exec.Command(sanitzedParams[0], sanitzedParams[1:]...)

	return cmd.Start()
}

func extractTotpUrl(data string) (string, error) {
	// make sure two consecutive URLs without white space between them are detected
	numUrls := strings.Count(strings.ToLower(data), "otpauth://totp/")

	if numUrls > 1 {
		return "", fmt.Errorf("Several potential otpauth://totp/ URLs found")
	}

	// The case of zero found URLs is handled below

	regEx := regexp.MustCompile(`(?i)otpauth://totp/\S+`)

	foundMatches := regEx.FindAllString(data, -1)
	if len(foundMatches) == 0 {
		return "", fmt.Errorf("No otpauth://totp/ URL found")
	}

	if len(foundMatches) > 1 {
		return "", fmt.Errorf("Several otpauth://totp/ URLs found")
	}

	return foundMatches[0], nil
}
