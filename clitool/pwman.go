package main

import (
	"flag"
	"fmt"
	"os"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
)

const defaulPbKdf = fcrypt.PbKdfArgon2id

// CmdContext contains data which is common to all commands
type CmdContext struct {
	client pwsrvbase.PwStorer
	//pbKdfId string
}

// NewContext creates a new command context
func NewContext() *CmdContext {
	return &CmdContext{
		//client: pwsrvbase.NewGenericJSONClient(pwsrvbase.NewSocketTransactor(pwsrvbase.PwServPort)),
		client: pwsrvbase.NewGenericJSONClient(pwsrvbase.NewUDSTransactor()),
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

	password, err := GetSecurePasswordVerified(enterPwText, reenterPwText)
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	plainBytes, err := os.ReadFile(*inFile)
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	if *outFile != "" {
		// Encrypt and write result to file
		err = fcrypt.SaveEncData(plainBytes, password, *outFile, defaulPbKdf)
		if err != nil {
			return fmt.Errorf("Unable to encrypt file: %v", err)
		}
	} else {
		// Encrypt and write result to stdout
		encBytes, err := fcrypt.EncryptBytes(&password, plainBytes, defaulPbKdf)
		if err != nil {
			return fmt.Errorf("Unable to encrypt file: %v", err)
		}

		fmt.Println(string(encBytes))
	}

	return nil
}

// InitCommand creates an encrypted emtpy password safe
func (c *CmdContext) InitCommand(args []string) error {
	encFlags := flag.NewFlagSet("pwman init", flag.ContinueOnError)
	outFile := encFlags.String("o", "", "Output file. Stdout if not specified")

	err := encFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *outFile == "" {
		return fmt.Errorf("No output file specified")
	}

	password, err := GetSecurePasswordVerified(enterPwText, reenterPwText)
	if err != nil {
		return fmt.Errorf("Unable to initialize password safe: %v", err)
	}

	gjots := fcrypt.MakeGjotsEmpty(defaulPbKdf)

	return gjots.SerializeEncrypted(*outFile, password)
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

	password, err := getPassword(enterPwText, c.client, *inFile)
	if err != nil {
		return fmt.Errorf("Error decrypting file: %v", err)
	}

	encBytes, err := os.ReadFile(*inFile)
	if err != nil {
		return fmt.Errorf("Error decrypting file: %v", err)
	}

	clearData, _, err := fcrypt.DecryptBytes(&password, encBytes)
	if err != nil {
		return fmt.Errorf("Error decrypting file: %v", err)
	}

	if *outFile == "" {
		fmt.Print(string(clearData))
	} else {
		err = os.WriteFile(*outFile, clearData, 0600)
	}

	return err
}

// PwdCommand checks the password and hands it to a PwStorer if it is correct
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

	password, err := GetSecurePassword(enterPwText)
	if err != nil {
		return fmt.Errorf("Unable to verify password: %v", err)
	}

	println()

	// Verify password
	_, err = fcrypt.MakeGjotsFromFile(*inFile, password)
	if err != nil {
		return fmt.Errorf("Unable to verify password: %v", err)
	}

	fullName, err := MakePasswordName(*inFile)
	if err != nil {
		return fmt.Errorf("Unable to set password: %v", err)
	}

	err = c.client.SetPassword(fullName, password)
	if err != nil {
		return fmt.Errorf("Unable to set password in pwserve: %v", err)
	}

	return nil
}

// ResetCommand deletes the password from pwserv
func (c *CmdContext) ResetCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman rst", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File holding password safe")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No file specified")
	}

	fullName, err := MakePasswordName(*inFile)
	if err != nil {
		return fmt.Errorf("Unable to reset password: %v", err)
	}

	err = c.client.ResetPassword(fullName)
	if err != nil {
		return fmt.Errorf("Unable to reset password in pwserve: %v", err)
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

func (c *CmdContext) RenameCommand(args []string) error {
	renFlags := flag.NewFlagSet("pwman ren", flag.ContinueOnError)
	inFile := renFlags.String("i", "", "File to decrypt")
	key := renFlags.String("k", "", "Key of entry to rename")
	newKey := renFlags.String("n", "", "New key to use for entry")

	err := renFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *inFile == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	if *newKey == "" {
		return fmt.Errorf("No new key specified")
	}

	return transact(
		func(g *fcrypt.GjotsFile) error {
			return g.RenameEntry(*key, *newKey)

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

	rawValue, err := os.ReadFile(*dataFile)
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
	subcommParser := NewSubcommandParser()
	ctx := NewContext()

	subcommParser.AddCommand("enc", ctx.EncryptCommand, "Encrypts a file")
	subcommParser.AddCommand("dec", ctx.DecryptCommand, "Decrypts a file")
	subcommParser.AddCommand("list", ctx.ListCommand, "Lists keys of entries in a file")
	subcommParser.AddCommand("get", ctx.GetCommand, "Get an entry from a file")
	subcommParser.AddCommand("put", ctx.UpsertCommand, "Adds/modifies an entry in a file")
	subcommParser.AddCommand("ren", ctx.RenameCommand, "Renames an entry in a file")
	subcommParser.AddCommand("del", ctx.DeleteCommand, "Deletes an entry from a file")
	subcommParser.AddCommand("pwd", ctx.PwdCommand, "Checks the password and transfers it to pwserv")
	subcommParser.AddCommand("rst", ctx.ResetCommand, "Deletes the password from pwserv")
	subcommParser.AddCommand("init", ctx.InitCommand, "Creates an empty password safe")

	subcommParser.Execute()
}
