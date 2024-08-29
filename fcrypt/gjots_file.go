package fcrypt

import (
	"encoding/json"
	"fmt"
)

type jotsFileManager struct {
	jotser   *gjotsRaw
	printers map[string]ValuePrinter
}

func NewJotsFileManager() *jotsFileManager {
	return &jotsFileManager{
		jotser:   nil,
		printers: map[string]ValuePrinter{},
	}
}

func (j *jotsFileManager) Open(inFile string, password string) (Gjotser, error) {
	h, err := j.makeGjotsFromFile(inFile, password)
	if err != nil {
		return nil, err
	}

	j.jotser = h

	return j.jotser, nil
}

func (j *jotsFileManager) SetPrinters(prts map[string]ValuePrinter) {
	j.printers = prts
}

func (j *jotsFileManager) Close(inFile string, password string) error {
	return j.saveGjotsToFile(inFile, password)
}

func (j *jotsFileManager) Init(pbkdfId string) (Gjotser, error) {
	j.jotser = makeGjotsRaw(pbkdfId, j.printers)

	return j.jotser, nil
}

// makeGjotsFromFile loads and decrypts a file
func (j *jotsFileManager) makeGjotsFromFile(inFile string, password string) (*gjotsRaw, error) {
	clearData, kdfId, err := LoadEncData(password, inFile)
	if err != nil {
		return nil, err
	}

	gjotsData := []gjotsEntry{}

	err = json.Unmarshal(clearData, &gjotsData)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	gjotsFile := makeGjotsRaw(kdfId, j.printers)
	gjotsFile.FromSequence(gjotsData)

	return gjotsFile, nil
}

// saveGjotsToFile serializes the saves the data
func (j *jotsFileManager) saveGjotsToFile(fileName string, password string) error {
	entries := j.jotser.ToSeqence()

	serialized, err := json.MarshalIndent(&entries, "", "    ")
	if err != nil {
		return fmt.Errorf("Unable to serialize data: %v", err)
	}

	return SaveEncData(serialized, password, fileName, j.jotser.pbKdfId)
}