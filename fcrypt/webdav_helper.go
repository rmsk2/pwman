package fcrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	webdav "pwman/fcrypt/gowebdav"
	"strings"
)

type webDavHelper struct {
}

func NewWebDavHelper() GjWebdav {
	return &webDavHelper{}
}

func (w *webDavHelper) WriteFile(data []byte, userId string, password string, fileName string) error {
	endPoint, name, err := w.Split(fileName)
	if err != nil {
		return fmt.Errorf("Unable to write WebDAV data: %v", err)
	}

	httpClient := webdav.HTTPClientWithBasicAuth(nil, userId, password)
	webdavClient, err := webdav.NewClient(httpClient, endPoint)
	if err != nil {
		return fmt.Errorf("Unable to write WebDAV data: %v", err)
	}

	wr, err := webdavClient.Create(context.TODO(), name)
	if err != nil {
		return fmt.Errorf("Unable to write WebDAV data: %v", err)
	}
	defer func() { wr.Close() }()

	buf := bytes.NewBuffer(data)

	_, err = io.Copy(wr, buf)
	if err != nil {
		return fmt.Errorf("Unable to write WebDAV data: %v", err)
	}

	return nil
}

func (w *webDavHelper) Split(name string) (string, string, error) {
	if len(name) < 11 {
		return "", "", fmt.Errorf("Path %s not well formed", name)
	}

	if strings.Index(name, "https://") != 0 {
		return "", "", fmt.Errorf("Path %s not well formed", name)
	}

	if strings.HasSuffix(name, "/") {
		return "", "", fmt.Errorf("Path %s not well formed", name)
	}

	lastIndex := strings.LastIndex(name, "/")

	endPoint := name[:lastIndex]
	// Skip /. This is safe because the string does not end with a / as tested above
	file := name[lastIndex+1:]

	if (endPoint == "") || (file == "") {
		return "", "", fmt.Errorf("Path %s not well formed", name)
	}

	return endPoint, file, nil
}

func (w *webDavHelper) ReadFile(userId string, password string, fileName string) ([]byte, error) {
	endPoint, name, err := w.Split(fileName)
	if err != nil {
		return nil, fmt.Errorf("Unable to read WebDAV data: %v", err)
	}

	httpClient := webdav.HTTPClientWithBasicAuth(nil, userId, password)

	webdavClient, err := webdav.NewClient(httpClient, endPoint)
	if err != nil {
		return nil, fmt.Errorf("Unable to read WebDAV data: %v", err)
	}

	r, err := webdavClient.Open(context.TODO(), name)
	if err != nil {
		return nil, fmt.Errorf("Unable to read WebDAV data: %v", err)
	}
	defer func() { r.Close() }()

	buf := bytes.NewBuffer(make([]byte, 0, 32768))

	_, err = io.Copy(buf, r)
	if err != nil {
		return nil, fmt.Errorf("Unable to read WebDAV data: %v", err)
	}

	res, err := io.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("Unable to read WebDAV data: %v", err)
	}

	return res, nil
}
