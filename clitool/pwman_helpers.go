package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

const enterPwText = "Please enter password: "
const reenterPwText = "Please reenter password: "
const envVarPwmanFile = "PWMANFILE"
const envVarPwmanClip = "PWMANCLIP"
const envVarPwmanBkp = "PWMANBKP"
const envVarViewer = "RUSTPWMAN_VIEWER"

type procFunc func(g fcrypt.Gjotser) error

// MakePasswordName derives a name for a password form the name of a encrypted container
func MakePasswordName(fileName string) (string, error) {
	var fullName string
	var err error

	if fileName == "*" {
		return fileName, nil
	}

	if !(strings.HasPrefix(fileName, "https://") || strings.HasPrefix(fileName, "http://")) {
		fullName, err = filepath.Abs(fileName)
		if err != nil {
			return "", err
		}
	} else {
		fullName = fileName
	}

	mac := hmac.New(sha256.New, obfuscator)
	_, err = mac.Write([]byte(fullName))
	if err != nil {
		return "", fmt.Errorf("unable to calc cache address: %v", err)
	}
	sum := mac.Sum(nil)[:16]

	return fmt.Sprintf("PWMAN:%x", sum), nil
}

// GetSecurePassword reads a password from the console
func GetSecurePassword(msg string) (string, error) {
	return GetSecurePasswordExt(msg, true)
}

// GetSecurePasswordExt reads a password from the console
func GetSecurePasswordExt(msg string, newLine bool) (string, error) {
	print(msg) // print to stderr instead of stdout
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	if newLine {
		println()
	}

	return string(password), nil
}

// GetSecurePasswordVerified reads a new password from the console and verifies its value by letting the user entering it twice
func GetSecurePasswordVerified(msg1, msg2 string) (string, error) {
	password1, err := GetSecurePassword(msg1)
	if err != nil {
		return "", fmt.Errorf("Unable to read password: %v", err)
	}

	//println()

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

func getBackupFileName(cmdLineParam *string) string {
	return getParamOrEnvVar(cmdLineParam, envVarPwmanBkp)
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

type SecondFunc func(currentTime time.Time)

type BackgroundTask struct {
	wg   sync.WaitGroup
	f    SecondFunc
	done chan struct{}
}

func NewBackgroundTask(f SecondFunc) *BackgroundTask {
	return &BackgroundTask{
		f:    f,
		done: make(chan struct{}),
	}
}

func (b *BackgroundTask) eachSecond() {
	defer b.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	b.f(time.Now())

	for {
		select {
		case <-b.done:
			return
		case t := <-ticker.C:
			b.f(t)
		}
	}
}

func (b *BackgroundTask) Start() {
	b.wg.Add(1)
	go b.eachSecond()
}

func (b *BackgroundTask) End() {
	close(b.done)
	b.wg.Wait()
}
