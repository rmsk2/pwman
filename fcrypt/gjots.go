package fcrypt

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
)

// GjotsEntry represents an entry in a gjots file
type GjotsEntry struct {
	Key  string
	Text string
}

// GjotsFile represents the contents of a gjots file
type GjotsFile struct {
	Entries   []GjotsEntry
	EntryDict map[string]string
	pbKdfId   string
}

// MakeGjotsEmpty creates an empty GjotsFile data structure
func MakeGjotsEmpty(kdfId string) *GjotsFile {
	return &GjotsFile{
		Entries:   []GjotsEntry{},
		EntryDict: map[string]string{},
		pbKdfId:   kdfId,
	}
}

// MakeGjotsFromFile loads and decrypts a file
func MakeGjotsFromFile(inFile string, password string) (*GjotsFile, error) {
	encBytes, err := ioutil.ReadFile(inFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	clearData, kdfId, err := DecryptBytes(&password, encBytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	gjotsData := []GjotsEntry{}

	err = json.Unmarshal(clearData, &gjotsData)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	gjotsFile := &GjotsFile{
		Entries: gjotsData,
		pbKdfId: kdfId,
	}

	gjotsFile.toDict()

	return gjotsFile, nil
}

// SerializeEncrypted serializes the saves the data
func (g *GjotsFile) SerializeEncrypted(fileName string, password string) error {
	g.fromDict()

	serialized, err := json.MarshalIndent(&g.Entries, "", "    ")
	if err != nil {
		return fmt.Errorf("Unable to serialize data: %v", err)
	}

	return SaveEncData(serialized, password, fileName, g.pbKdfId)
}

// PrintKeyList prints all keys in the file
func (g *GjotsFile) PrintKeyList() {
	keys := make([]string, 0, len(g.EntryDict))
	for i := range g.EntryDict {
		keys = append(keys, i)
	}

	sort.Strings(keys)

	for _, j := range keys {
		fmt.Println(j)
	}
}

func (g *GjotsFile) toDict() {
	res := map[string]string{}

	for _, j := range g.Entries {
		res[j.Key] = j.Text
	}

	g.EntryDict = res
}

func (g *GjotsFile) fromDict() {
	g.Entries = []GjotsEntry{}

	for i, j := range g.EntryDict {
		newEntry := GjotsEntry{
			Key:  i,
			Text: j,
		}

		g.Entries = append(g.Entries, newEntry)
	}
}

// PrintEntry searches for an entry and if found prints it
func (g *GjotsFile) PrintEntry(key string) error {
	value, ok := g.EntryDict[key]
	if !ok {
		return fmt.Errorf("Key '%s' not found", key)
	}

	fmt.Println(value)

	return nil
}

// DeleteEntry deletes an entry from the file
func (g *GjotsFile) DeleteEntry(key string) error {
	_, ok := g.EntryDict[key]
	if !ok {
		return fmt.Errorf("Key '%s' not found", key)
	}

	delete(g.EntryDict, key)

	return nil
}

// UpsertEntry adds/modifies an entry from the file
func (g *GjotsFile) UpsertEntry(key string, data string) bool {
	_, ok := g.EntryDict[key]
	g.EntryDict[key] = data

	return ok
}
