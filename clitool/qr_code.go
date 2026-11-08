package main

import (
	"image/png"
	"os"
	"os/exec"
	"pwman/fcrypt"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

func createQrCode(data string, outFile string, size int, extract bool) error {
	var err error
	var qrCode barcode.Barcode

	if extract {
		data, err = fcrypt.ExtractTotpUrl(data)
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
