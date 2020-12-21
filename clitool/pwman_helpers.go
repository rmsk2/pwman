package main

import (
	"fmt"
	"io/ioutil"
	"pwman/fcrypt"
	"pwman/pwsrvbase"

	"golang.org/x/crypto/ssh/terminal"
)

const pwName = "PWMAN"
const enterPwText = "Please enter password: "

type procFunc func(g *fcrypt.GjotsFile) error

// GetSecurePassword reads a password from the console
func GetSecurePassword(msg string) (string, error) {
	print(msg) // print to stderr instead of stdout
	password, err := terminal.ReadPassword(0)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

func getPassword(msg string, client pwsrvbase.PwStorer) (string, error) {
	pw, err := client.GetPassword(pwName)
	if (err == nil) && (pw != "") {
		return pw, nil
	}

	password, err := GetSecurePassword(msg)
	if err != nil {
		return "", err
	}

	println()

	return password, nil
}

func decryptFile(inFile *string, client pwsrvbase.PwStorer) ([]byte, string, error) {
	password, err := getPassword(enterPwText, client)
	if err != nil {
		return nil, "", err
	}

	encBytes, err := ioutil.ReadFile(*inFile)
	if err != nil {
		return nil, "", err
	}

	clearData, err := fcrypt.DecryptBytes(&password, encBytes)
	if err != nil {
		return nil, "", err
	}

	return clearData, password, nil
}

func transact(proc procFunc, inFile *string, doWrite bool, client pwsrvbase.PwStorer) error {
	password, err := getPassword(enterPwText, client)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from file '%s': %v", *inFile, err)
	}

	gjotsData, err := fcrypt.MakeFromEncryptedFile(*inFile, password)
	if err != nil {
		return fmt.Errorf("Decryption failed: %v", err)
	}

	err = proc(gjotsData)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from file '%s': %v", *inFile, err)
	}

	if doWrite {
		return gjotsData.SaveEncryptedFile(*inFile, password)
	}

	return nil
}
