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

func evalHttpError(statusCode int) error {
	if (statusCode >= 200) && (statusCode < 300) {
		return nil
	}

	switch statusCode {
	case 404:
		return fmt.Errorf("File not found (HTTP 404)")
	case 401:
		return fmt.Errorf("Unauthorized (HTTP 401)")
	default:
		return fmt.Errorf("HTTP error %d", statusCode)
	}
}

func (s *simpleWebDav) FileExists(userId string, password string, fileName string) (bool, error) {
	body := `<?xml version="1.0" encoding="utf-8" ?>
		<D:propfind xmlns:D="DAV:">
			<D:prop><D:getcontentlength/></D:prop>
		</D:propfind>
	`

	client := &http.Client{}

	req, err := http.NewRequest("PROPFIND", fileName, bytes.NewReader([]byte(body)))
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(userId, password)
	req.Header.Set("depth", "0")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { resp.Body.Close() }()

	// ignore result
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	err = evalHttpError(resp.StatusCode)
	if err != nil {
		if resp.StatusCode == 404 {
			return false, nil
		} else {
			return false, err
		}
	}

	return true, nil
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

	return evalHttpError(resp.StatusCode)
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

	err = evalHttpError(resp.StatusCode)
	if err != nil {
		return nil, err
	}

	return data, nil
}
