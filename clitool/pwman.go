package main

import (
	"bellonet/util"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"pwman/cliutil"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"strconv"
	"time"
)

const pwmanEnvVar = "PWMAN_PASSWORD"

type pwAPIClient struct {
	port uint16
}

// NewPwAPIClient returns an initialized pwAPIClient
func newPwAPIClient(port uint16) *pwAPIClient {
	return &pwAPIClient{
		port: port,
	}
}

func (p *pwAPIClient) makeURL(name string) string {
	portStr := strconv.FormatUint(uint64(p.port), 10)
	portSpec := net.JoinHostPort("localhost", portStr)
	url := fmt.Sprintf("http://%s%s%s", portSpec, pwsrvbase.APIURL, name)

	return url
}

func (p *pwAPIClient) SetPassword(name string, password string) error {
	url := p.makeURL(name)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(password)))
	if err != nil {
		return err
	}

	_, err = DoHTTPRequest(req)
	if err != nil {
		return err
	}

	return nil
}

func (p *pwAPIClient) GetPassword(name string) (string, error) {
	url := p.makeURL(name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	data, err := util.DoHTTPRequest(req)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// DoHTTPRequest performs an HTTP request and returns the data returned by the server
func DoHTTPRequest(req *http.Request) ([]byte, error) {
	timeout := time.Duration(60 * time.Second)
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if 200 != resp.StatusCode {
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, resp.Status)
	}

	return body, nil
}

// EncryptCommand encrypts a file and writes the result to stdout
func EncryptCommand(args []string) error {
	encFlags := flag.NewFlagSet("pwman enc", flag.ContinueOnError)
	inFile := encFlags.String("i", "", "File to encrypt")
	outFile := encFlags.String("o", "", "Output file. Stdout if not specified")

	err := encFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	password1, err := getPassword(enterPwText)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}

	password2, err := getPassword("Please reenter password:")
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}

	if password1 != password2 {
		return fmt.Errorf("Passwords not equal")
	}

	plainBytes, err := ioutil.ReadFile(*inFile)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}
	if *outFile != "" {
		return fcrypt.SaveEncData(plainBytes, password1, *outFile)
	}

	encBytes, err := fcrypt.EncryptBytes(&password1, plainBytes)
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	fmt.Println(string(encBytes))

	return nil
}

// DecryptCommand decrypts a file and writes the result to stdout
func DecryptCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman dec", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File to decrypt")
	outFile := decFlags.String("o", "", "Output file. Stdout if not specified")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	clearData, _, err := decryptFile(inFile)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}

	if *outFile == "" {
		fmt.Print(string(clearData))
	} else {
		err = ioutil.WriteFile(*outFile, clearData, 0600)
	}

	return nil
}

// PwdCommand checks the password and prints it to stdout if correct
func PwdCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman pwd", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File to decrypt")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	_, password, err := decryptFile(inFile)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}

	client := newPwAPIClient(pwsrvbase.PwServPort)

	err = client.SetPassword(pwName, password)
	if err != nil {
		return fmt.Errorf("Unable to set password in pwserve: %v", err)
	}

	return nil
}

// VarCommand prints the environment variable used by pwman
func VarCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman var", flag.ContinueOnError)

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	fmt.Println(pwmanEnvVar)

	return nil
}

// ListCommand decrypts a file and prints a list of all keys to stdout
func ListCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman list", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File to decrypt")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	return transact(
		func(g *fcrypt.GjotsFile) error {
			fmt.Println()
			g.PrintKeyList()

			return nil

		}, inFile, false,
	)
}

// GetCommand decrypts and searches in a file and writes the result to stdout
func GetCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman get", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File to decrypt")
	key := decFlags.String("k", "", "Key to search")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	return transact(
		func(g *fcrypt.GjotsFile) error {
			fmt.Println()

			err = g.PrintEntry(*key)
			if err != nil {
				return err
			}

			return nil

		}, inFile, false,
	)
}

// DeleteCommand deletes an entry from a file
func DeleteCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman del", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File to decrypt")
	key := decFlags.String("k", "", "Key to delete")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	return transact(
		func(g *fcrypt.GjotsFile) error {
			return g.DeleteEntry(*key)
		}, inFile, true,
	)
}

// UpsertCommand adds/modifies an entry in a file
func UpsertCommand(args []string) error {
	putFlags := flag.NewFlagSet("pwman get", flag.ContinueOnError)
	inFile := putFlags.String("i", "", "File to decrypt")
	key := putFlags.String("k", "", "Key of entry to modify")
	dataFile := putFlags.String("v", "", "File containing value to associate with path/name")

	err := putFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	if *dataFile == "" {
		return fmt.Errorf("No value file name specified")
	}

	rawValue, err := ioutil.ReadFile(*dataFile)
	if err != nil {
		return fmt.Errorf("Unable to load value data from '%s': %v", *dataFile, err)
	}

	return transact(
		func(g *fcrypt.GjotsFile) error {
			if g.UpsertEntry(*key, string(rawValue)) {
				fmt.Println("Entry replaced")
			} else {
				fmt.Println("Entry added")
			}

			return nil

		}, inFile, true,
	)
}

func main() {
	subcommParser := cliutil.NewSubcommandParser()

	subcommParser.AddCommand("enc", EncryptCommand, "Encrypts a file")
	subcommParser.AddCommand("dec", DecryptCommand, "Decrypts a file")
	subcommParser.AddCommand("list", ListCommand, "Lists keys of entries in a file")
	subcommParser.AddCommand("get", GetCommand, "Get an entry from a file")
	subcommParser.AddCommand("put", UpsertCommand, "Adds/modifies an entry in a file")
	subcommParser.AddCommand("del", DeleteCommand, "Deletes an entry from a file")
	subcommParser.AddCommand("var", VarCommand, "Prints name of environment variable")
	subcommParser.AddCommand("pwd", PwdCommand, "Checks the password and transfers it to pwserv")

	subcommParser.Execute()
}
