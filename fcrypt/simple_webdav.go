package fcrypt

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

type simpleWebDav struct {
}

func NewSimpleWebDav() GjWebdav {
	return &simpleWebDav{}
}

func (s *simpleWebDav) WriteFile(data []byte, userId string, password string, fileName string) error {
	client := &http.Client{}

	req, err := http.NewRequest("PUT", fileName, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.SetBasicAuth(userId, password)
	req.Header.Set("content-type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { resp.Body.Close() }()

	// ignore result
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if (resp.StatusCode < 200) || (resp.StatusCode >= 300) {
		return fmt.Errorf("Writing file failed. HTTP error: %d", resp.StatusCode)
	}

	return nil
}

func (s *simpleWebDav) ReadFile(userId string, password string, fileName string) ([]byte, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", fileName, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(userId, password)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if (resp.StatusCode < 200) || (resp.StatusCode >= 300) {
		return nil, fmt.Errorf("Reading file failed: HTTP error: %d", resp.StatusCode)
	}

	return data, nil
}
