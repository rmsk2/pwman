package fcrypt

import (
	"fmt"
	"sort"
)

const TxtPrt = "text"
const DefaultPrt = TxtPrt

// gjotsEntry represents an entry in a gjots file
type gjotsEntry struct {
	Key  string
	Text string
}

// gjotsRaw represents the contents of a gjots file
type gjotsRaw struct {
	EntryDict map[string]string
	pbKdfId   string
}

// makeGjotsRaw creates an empty GjotsFile data structure
func makeGjotsRaw(kdfId string) *gjotsRaw {
	res := &gjotsRaw{
		EntryDict: map[string]string{},
		pbKdfId:   kdfId,
	}

	return res
}

func (g *gjotsRaw) ToSeqence() []gjotsEntry {
	result := []gjotsEntry{}

	for i, j := range g.EntryDict {
		newEntry := gjotsEntry{
			Key:  i,
			Text: j,
		}

		result = append(result, newEntry)
	}

	return result
}

func (g *gjotsRaw) FromSequence(entries []gjotsEntry) {
	res := map[string]string{}

	for _, j := range entries {
		res[j.Key] = j.Text
	}

	g.EntryDict = res
}

// PrintKeyList prints all keys in the file
func (g *gjotsRaw) PrintKeyList() error {
	keys, _ := g.GetKeyList()

	for _, j := range keys {
		fmt.Printf("\"%s\"\n", j)
	}

	return nil
}

func (g *gjotsRaw) simplePrint(key, value string) error {
	fmt.Printf("----- %s -----\n", key)
	fmt.Println(value)

	return nil
}

// PrintEntry searches for an entry and if found prints it
func (g *gjotsRaw) PrintEntry(key string) error {
	value, err := g.GetEntry(key)
	if err != nil {
		return err
	}

	_ = g.simplePrint(key, value)

	return nil
}

// GetKeyList returns the list of the keys contained in the password file
func (g *gjotsRaw) GetKeyList() ([]string, error) {
	keys := make([]string, 0, len(g.EntryDict))
	for i := range g.EntryDict {
		keys = append(keys, i)
	}

	sort.Strings(keys)

	return keys, nil
}

// GetEntry returns the data identified by key
func (g *gjotsRaw) GetEntry(key string) (string, error) {
	value, ok := g.EntryDict[key]
	if !ok {
		return "", fmt.Errorf("Key '%s' not found", key)
	}

	return value, nil
}

// DeleteEntry deletes an entry from the file
func (g *gjotsRaw) DeleteEntry(key string) error {
	_, ok := g.EntryDict[key]
	if !ok {
		return fmt.Errorf("Key '%s' not found", key)
	}

	delete(g.EntryDict, key)

	return nil
}

// RenameEntry renames an entry
func (g *gjotsRaw) RenameEntry(key string, newKey string) error {
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
func (g *gjotsRaw) UpsertEntry(key string, data string) (bool, error) {
	_, ok := g.EntryDict[key]
	g.EntryDict[key] = data

	return ok, nil
}
