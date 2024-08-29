package fcrypt

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
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
	printers  map[string]ValuePrinter
}

// makeGjotsRaw creates an empty GjotsFile data structure
func makeGjotsRaw(kdfId string, prts map[string]ValuePrinter) *gjotsRaw {
	res := &gjotsRaw{
		EntryDict: map[string]string{},
		pbKdfId:   kdfId,
		printers:  prts,
	}

	res.printers["simple"] = res.simplePrint

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

func (g *gjotsRaw) PrintAllWithFormat(format string) error {
	printer, ok := g.printers[format]
	if !ok {
		return fmt.Errorf("Unknown printer format: '%s'", format)
	}

	keys := make([]string, 0, len(g.EntryDict))
	for i := range g.EntryDict {
		keys = append(keys, i)
	}

	sort.Strings(keys)

	for _, i := range keys {
		value, err := g.GetEntry(i)
		if err != nil {
			return err
		}

		err = printer(i, value)
		if err != nil {
			return fmt.Errorf("Unable to print value: %v", err)
		}
	}

	return nil
}

// PrintAll prints the whole contents of the password file
func (g *gjotsRaw) PrintAll() error {
	return g.PrintAllWithFormat(DefaultPrt)
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

func PrintText(key string, value string) error {
	lineLen := 80
	stars := "***"
	txtLen := utf8.RuneCountInString(key)
	fillLen := lineLen - txtLen - 2*len(stars)
	var fillerLeft string
	var fillerRight string

	if fillLen <= 0 {
		fillerLeft = " "
		fillerRight = " "
	} else {
		if fillLen%2 == 0 {
			fillerLeft = strings.Repeat(" ", fillLen/2)
			fillerRight = strings.Repeat(" ", fillLen/2)
		} else {
			fillerLeft = strings.Repeat(" ", fillLen/2)
			fillerRight = strings.Repeat(" ", fillLen/2+1)
		}
	}

	title := fmt.Sprintf("%s%s%s%s%s", stars, fillerLeft, key, fillerRight, stars)
	e := strings.Repeat(" ", utf8.RuneCountInString(title)-2*len(stars))
	empty := fmt.Sprintf("%s%s%s", stars, e, stars)
	bar := strings.Repeat("*", utf8.RuneCountInString(title))
	fmt.Println(bar)
	fmt.Println(empty)
	fmt.Println(title)
	fmt.Println(empty)
	fmt.Println(bar)
	fmt.Println(value)
	fmt.Println()

	return nil
}
