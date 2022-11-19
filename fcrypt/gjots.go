package fcrypt

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// gjotsEntry represents an entry in a gjots file
type gjotsEntry struct {
	Key  string
	Text string
}

// gjotsFile represents the contents of a gjots file
type gjotsFile struct {
	Entries   []gjotsEntry
	EntryDict map[string]string
	pbKdfId   string
}

// MakeGjotsEmpty creates an empty GjotsFile data structure
func makeGjotsEmpty(kdfId string) (Gjotser, error) {
	return &gjotsFile{
		Entries:   []gjotsEntry{},
		EntryDict: map[string]string{},
		pbKdfId:   kdfId,
	}, nil
}

// MakeGjotsFromFile loads and decrypts a file
func makeGjotsFromFile(inFile string, password string) (Gjotser, error) {
	encBytes, err := os.ReadFile(inFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	clearData, kdfId, err := DecryptBytes(&password, encBytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	gjotsData := []gjotsEntry{}

	err = json.Unmarshal(clearData, &gjotsData)
	if err != nil {
		return nil, fmt.Errorf("Unable to load encrypted data from file '%s': %v", inFile, err)
	}

	gjotsFile := &gjotsFile{
		Entries: gjotsData,
		pbKdfId: kdfId,
	}

	gjotsFile.toDict()

	return gjotsFile, nil
}

// SerializeEncrypted serializes the saves the data
func (g *gjotsFile) SerializeEncrypted(fileName string, password string) error {
	g.fromDict()

	serialized, err := json.MarshalIndent(&g.Entries, "", "    ")
	if err != nil {
		return fmt.Errorf("Unable to serialize data: %v", err)
	}

	return SaveEncData(serialized, password, fileName, g.pbKdfId)
}

func (g *gjotsFile) toDict() {
	res := map[string]string{}

	for _, j := range g.Entries {
		res[j.Key] = j.Text
	}

	g.EntryDict = res
}

func (g *gjotsFile) fromDict() {
	g.Entries = []gjotsEntry{}

	for i, j := range g.EntryDict {
		newEntry := gjotsEntry{
			Key:  i,
			Text: j,
		}

		g.Entries = append(g.Entries, newEntry)
	}
}

// PrintKeyList prints all keys in the file
func (g *gjotsFile) PrintKeyList() error {
	keys, _ := g.GetKeyList()

	for _, j := range keys {
		fmt.Printf("\"%s\"\n", j)
	}

	return nil
}

// PrintEntry searches for an entry and if found prints it
func (g *gjotsFile) PrintEntry(key string) error {
	value, err := g.GetEntry(key)
	if err != nil {
		return err
	}

	fmt.Printf("----- %s -----\n", key)
	fmt.Println(value)

	return nil
}

// GetKeyList returns the list of the keys contained in the password file
func (g *gjotsFile) GetKeyList() ([]string, error) {
	keys := make([]string, 0, len(g.EntryDict))
	for i := range g.EntryDict {
		keys = append(keys, i)
	}

	sort.Strings(keys)

	return keys, nil
}

// GetEntry returns the data identified by key
func (g *gjotsFile) GetEntry(key string) (string, error) {
	value, ok := g.EntryDict[key]
	if !ok {
		return "", fmt.Errorf("Key '%s' not found", key)
	}

	return value, nil
}

// DeleteEntry deletes an entry from the file
func (g *gjotsFile) DeleteEntry(key string) error {
	_, ok := g.EntryDict[key]
	if !ok {
		return fmt.Errorf("Key '%s' not found", key)
	}

	delete(g.EntryDict, key)

	return nil
}

// RenameEntry renames an entry
func (g *gjotsFile) RenameEntry(key string, newKey string) error {
	entry, err := g.GetEntry(key)
	if err != nil {
		return fmt.Errorf("Unable to rename entry: %v", err)
	}

	_, ok := g.EntryDict[newKey]
	if ok {
		return fmt.Errorf("Key '%s' already exists", newKey)
	}

	err = g.DeleteEntry(key)
	if err != nil {
		return fmt.Errorf("Unable to rename entry: %v", err)
	}

	_, _ = g.UpsertEntry(newKey, entry)

	return nil
}

// UpsertEntry adds/modifies an entry from the file. The return value is true if an existing value was updated
// it is false otherwise.
func (g *gjotsFile) UpsertEntry(key string, data string) (bool, error) {
	_, ok := g.EntryDict[key]
	g.EntryDict[key] = data

	return ok, nil
}
