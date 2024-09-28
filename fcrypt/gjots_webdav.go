package fcrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"pwman/printers"
)

type WebDavCredGetter func() (string, string, error)

type GjWebdav interface {
	WriteFile(data []byte, userId string, password string, fileName string) error
	ReadFile(userId string, password string, fileName string) ([]byte, error)
}

type jotsWebdavManager struct {
	jotser   *gjotsRaw
	dav      GjWebdav
	pwGet    WebDavCredGetter
	printers map[string]printers.ValuePrinter
}

func NewGjotsWebdav(d GjWebdav, g WebDavCredGetter) GjotsManager {
	return &jotsWebdavManager{
		jotser:   nil,
		dav:      d,
		pwGet:    g,
		printers: map[string]printers.ValuePrinter{},
	}
}

func (j *jotsWebdavManager) GetRawData(inFile string) ([]byte, error) {
	uid, wbeDavPw, err := j.pwGet()
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve WebDAV password safe: %v", err)
	}

	encBytes, err := j.dav.ReadFile(uid, wbeDavPw, inFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve WebDAV password safe: %v", err)
	}

	return encBytes, nil
}

func (j *jotsWebdavManager) Open(inFile string, password string) (Gjotser, error) {
	uid, wbeDavPw, err := j.pwGet()
	if err != nil {
		return nil, fmt.Errorf("Unable to open WebDAV password safe: %v", err)
	}

	encBytes, err := j.dav.ReadFile(uid, wbeDavPw, inFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to open WebDAV password safe: %v", err)
	}

	clearData, kdfId, err := ReadEncData(password, bytes.NewBuffer(encBytes))
	if err != nil {
		return nil, fmt.Errorf("Unable to open WebDAV password safe: %v", err)
	}

	gjotsData := []gjotsEntry{}

	err = json.Unmarshal(clearData, &gjotsData)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	gjots := makeGjotsRaw(kdfId, j.printers)
	gjots.FromSequence(gjotsData)

	j.jotser = gjots

	return j.jotser, nil
}

func (j *jotsWebdavManager) SetPrinters(prts map[string]printers.ValuePrinter) {
	j.printers = prts
}

func (j *jotsWebdavManager) Init(pbkdfId string) (Gjotser, error) {
	j.jotser = makeGjotsRaw(pbkdfId, j.printers)

	return j.jotser, nil
}

func (j *jotsWebdavManager) Close(fileName string, password string) error {
	uid, wbeDavPw, err := j.pwGet()
	if err != nil {
		return fmt.Errorf("Unable to determine WebDAV credentials: %v", err)
	}

	entries := j.jotser.ToSeqence()

	serialized, err := json.MarshalIndent(&entries, "", "    ")
	if err != nil {
		return fmt.Errorf("Unable to Close WebDAV password safe: %v", err)
	}

	buf := bytes.NewBuffer(make([]byte, 0, 32768))
	err = WriteEncData(serialized, password, buf, j.jotser.pbKdfId)
	if err != nil {
		return fmt.Errorf("Unable to encrypt WebDAV data: %v", err)
	}

	encData, err := io.ReadAll(buf)
	if err != nil {
		return fmt.Errorf("Unable to read encrypted WebDAV data: %v", err)
	}

	return j.dav.WriteFile(encData, uid, wbeDavPw, fileName)
}
