package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"pwman/cliutil"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
)

// CmdContext contains data which is common to all commands
type CmdContext struct {
	client pwsrvbase.PwStorer
}

// NewContext creates a new command context
func NewContext() *CmdContext {
	return &CmdContext{
		client: pwsrvbase.NewPwAPIClient(pwsrvbase.PwServPort),
	}
}

// EncryptCommand encrypts a file and writes the result to stdout
func (c *CmdContext) EncryptCommand(args []string) error {
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

	password1, err := GetSecurePassword(enterPwText)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}

	password2, err := GetSecurePassword("Please reenter password:")
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
func (c *CmdContext) DecryptCommand(args []string) error {
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

	clearData, _, err := decryptFile(inFile, c.client)
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
func (c *CmdContext) PwdCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman pwd", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File to decrypt")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	_, password, err := decryptFile(inFile, c.client)
	if err != nil {
		return fmt.Errorf("Unable to load encrypted data from '%s': %v", *inFile, err)
	}

	err = c.client.SetPassword(pwName, password)
	if err != nil {
		return fmt.Errorf("Unable to set password in pwserve: %v", err)
	}

	return nil
}

// ListCommand decrypts a file and prints a list of all keys to stdout
func (c *CmdContext) ListCommand(args []string) error {
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

		}, inFile, false, c.client,
	)
}

// GetCommand decrypts and searches in a file and writes the result to stdout
func (c *CmdContext) GetCommand(args []string) error {
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

		}, inFile, false, c.client,
	)
}

// DeleteCommand deletes an entry from a file
func (c *CmdContext) DeleteCommand(args []string) error {
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
		}, inFile, true, c.client,
	)
}

// UpsertCommand adds/modifies an entry in a file
func (c *CmdContext) UpsertCommand(args []string) error {
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

		}, inFile, true, c.client,
	)
}

func main() {
	subcommParser := cliutil.NewSubcommandParser()
	ctx := NewContext()

	subcommParser.AddCommand("enc", ctx.EncryptCommand, "Encrypts a file")
	subcommParser.AddCommand("dec", ctx.DecryptCommand, "Decrypts a file")
	subcommParser.AddCommand("list", ctx.ListCommand, "Lists keys of entries in a file")
	subcommParser.AddCommand("get", ctx.GetCommand, "Get an entry from a file")
	subcommParser.AddCommand("put", ctx.UpsertCommand, "Adds/modifies an entry in a file")
	subcommParser.AddCommand("del", ctx.DeleteCommand, "Deletes an entry from a file")
	subcommParser.AddCommand("pwd", ctx.PwdCommand, "Checks the password and transfers it to pwserv")

	subcommParser.Execute()
}
