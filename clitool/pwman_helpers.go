package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const enterPwText = "Please enter password: "
const reenterPwText = "Please reenter password: "
const envVarPwmanFile = "PWMANFILE"
const envVarPwmanClip = "PWMANCLIP"

type procFunc func(g fcrypt.Gjotser) error

// MakePasswordName derives a name for a password form the name of a encrypted container
func MakePasswordName(fileName string) (string, error) {
	var fullName string
	var err error

	if !strings.HasPrefix(fileName, "https://") {
		fullName, err = filepath.Abs(fileName)
		if err != nil {
			return "", err
		}
	} else {
		fullName = fileName
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
	password, err := term.ReadPassword(int(syscall.Stdin))
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

func getParamOrEnvVar(cmdLineParam *string, envVar string) string {
	if *cmdLineParam != "" {
		return *cmdLineParam
	}

	return os.Getenv(envVar)
}

func getPwSafeFileName(cmdLineParam *string) string {
	return getParamOrEnvVar(cmdLineParam, envVarPwmanFile)
}

func getClipboardCommand(cmdLineParam *string) string {
	return getParamOrEnvVar(cmdLineParam, envVarPwmanClip)
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

func transact(manager fcrypt.GjotsManager, proc procFunc, inFile *string, doWrite bool, client pwsrvbase.PwStorer) error {
	password, err := getPassword(enterPwText, client, *inFile)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from location '%s': %v", *inFile, err)
	}

	gjotsData, err := manager.Open(*inFile, password)
	if err != nil {
		return fmt.Errorf("Decryption failed: %v", err)
	}

	err = proc(gjotsData)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from location '%s': %v", *inFile, err)
	}

	if doWrite {
		return manager.Close(*inFile, password)
	}

	return nil
}
