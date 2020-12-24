package main

import (
	"fmt"
	"pwman/fcrypt"
	"pwman/pwsrvbase"

	"golang.org/x/crypto/ssh/terminal"
)

const pwName = "PWMAN"
const enterPwText = "Please enter password: "
const reenterPwText = "Please reenter password: "

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

func getPassword(msg string, client pwsrvbase.PwStorer) (string, error) {
	pw, err := client.GetPassword(pwName)
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
	password, err := getPassword(enterPwText, client)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from file '%s': %v", *inFile, err)
	}

	println()

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
