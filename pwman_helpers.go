package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"pwman/fcrypt"

	"golang.org/x/crypto/ssh/terminal"
)

const enterPwText = "Please enter password: "

type procFunc func(g *fcrypt.GjotsFile) error

func getPassword(msg string) (string, error) {
	if pw, ok := os.LookupEnv(pwmanEnvVar); ok && (pw != "") {
		return pw, nil
	}

	print(msg) // print to stderr instead of stdout
	password, err := terminal.ReadPassword(0)
	if err != nil {
		return "", err
	}

	println()

	return string(password), nil
}

func decryptFile(inFile *string) ([]byte, string, error) {
	password, err := getPassword(enterPwText)
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

func transact(proc procFunc, inFile *string, doWrite bool) error {
	password, err := getPassword(enterPwText)
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
