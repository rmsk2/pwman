package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"path/filepath"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"strings"

	"golang.org/x/term"
)

const enterPwText = "Please enter password: "
const reenterPwText = "Please reenter password: "

type procFunc func(g *fcrypt.GjotsFile) error

// MakePasswordName derives a name for a password form the name of a encrypted container
func MakePasswordName(fileName string) (string, error) {
	fullName, err := filepath.Abs(fileName)
	if err != nil {
		return "", err
	}

	hash := md5.New()
	_, err = io.Copy(hash, strings.NewReader(fullName))
	if err != nil {
		return "", err
	}
	sum := hash.Sum(nil)

	return fmt.Sprintf("PWMAN:%x", sum), nil
}

// GetSecurePassword reads a password from the console
func GetSecurePassword(msg string) (string, error) {
	print(msg) // print to stderr instead of stdout
	password, err := term.ReadPassword(0)
	if err != nil {
		return "", err
	}

	println()

	return string(password), nil
}

// GetSecurePasswordVerified reads a new password from the console and verifies its value by letting the user entering it twice
func GetSecurePasswordVerified(msg1, msg2 string) (string, error) {
	password1, err := GetSecurePassword(msg1)
	if err != nil {
		return "", fmt.Errorf("Unable to read password: %v", err)
	}

	println()

	password2, err := GetSecurePassword(msg2)
	if err != nil {
		return "", fmt.Errorf("Unable to read password: %v", err)
	}

	if password1 != password2 {
		return "", fmt.Errorf("Passwords not equal")
	}

	return password1, nil
}

func getPassword(msg string, client pwsrvbase.PwStorer, fileName string) (string, error) {
	fullName, err := MakePasswordName(fileName)
	if err != nil {
		return "", fmt.Errorf("Unable to get password: %v", err)
	}

	pw, err := client.GetPassword(fullName)
	if (err == nil) && (pw != "") {
		return pw, nil
	}

	password, err := GetSecurePassword(msg)
	if err != nil {
		return "", err
	}

	return password, nil
}

func transact(proc procFunc, inFile *string, doWrite bool, client pwsrvbase.PwStorer) error {
	password, err := getPassword(enterPwText, client, *inFile)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from file '%s': %v", *inFile, err)
	}

	gjotsData, err := fcrypt.MakeGjotsFromFile(*inFile, password)
	if err != nil {
		return fmt.Errorf("Decryption failed: %v", err)
	}

	err = proc(gjotsData)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from file '%s': %v", *inFile, err)
	}

	if doWrite {
		return gjotsData.SerializeEncrypted(*inFile, password)
	}

	return nil
}
