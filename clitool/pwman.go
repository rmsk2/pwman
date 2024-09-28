package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"pwman/pwsrvbase/domainsock"
	"strings"
)

const VersionInfo = "1.2.5"
const defaulPbKdf = fcrypt.PbKdfArgon2id

type ManagerCreator func(string) fcrypt.GjotsManager

// CmdContext contains data which is common to all commands
type CmdContext struct {
	client             pwsrvbase.PwStorer
	jotsManagerCreator ManagerCreator
}

// NewContext creates a new command context
func NewContext() *CmdContext {
	return &CmdContext{
		//client: pwsrvbase.NewGenericJSONClient(pwsrvbase.NewSocketTransactor(pwsrvbase.PwServPort)),
		client:             pwsrvbase.NewGenericJSONClient(domainsock.NewUDSTransactor()),
		jotsManagerCreator: fcrypt.GetGjotsManager,
	}
}

// InitCommand creates an encrypted emtpy password safe
func (c *CmdContext) InitCommand(args []string) error {
	initFlags := flag.NewFlagSet("pwman init", flag.ContinueOnError)
	outFile := initFlags.String("o", "", "Output file. Stdout if not specified")
	pbkfId := initFlags.String("k", fcrypt.PbKdfArgon2id, fmt.Sprintf("PBKDF to use. Allowed values: %s, %s, %s", fcrypt.PbKdfArgon2id, fcrypt.PbKdfScrypt, fcrypt.PbKdfSha256))

	checkDict := map[string]bool{
		fcrypt.PbKdfArgon2id: true,
		fcrypt.PbKdfScrypt:   true,
		fcrypt.PbKdfSha256:   true,
	}

	err := initFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *outFile == "" {
		return fmt.Errorf("No output file specified")
	}

	_, ok := checkDict[*pbkfId]
	if !ok {
		return fmt.Errorf("Unknown PBKDF: %s", *pbkfId)
	}

	password, err := GetSecurePasswordVerified(enterPwText, reenterPwText)
	if err != nil {
		return fmt.Errorf("Unable to initialize password safe: %v", err)
	}

	man := c.jotsManagerCreator(*outFile)

	_, err = man.Init(*pbkfId)
	if err != nil {
		return fmt.Errorf("Unable to initialize password safe: %v", err)
	}

	return man.Close(*outFile, password)
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

	clearData, _, err := fcrypt.LoadEncData(password, *inFile)
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
	inFile := decFlags.String("i", "", "File holding password safe")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	password, err := GetSecurePassword(enterPwText)
	if err != nil {
		return fmt.Errorf("Unable to verify password: %v", err)
	}

	println()

	man := c.jotsManagerCreator(safeName)

	// Verify password
	_, err = man.Open(safeName, password)
	if err != nil {
		return fmt.Errorf("Unable to verify password: %v", err)
	}

	fullName, err := MakePasswordName(safeName)
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

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No file specified")
	}

	fullName, err := MakePasswordName(safeName)
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
	inFile := decFlags.String("i", "", "File holding password safe")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			g.PrintKeyList()

			return nil

		}, &safeName, false, c.client,
	)
}

// PrintAllCommand decrypts a file and prints a list of all keys and values to stdout
func (c *CmdContext) PrintAllCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman all", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File holding password safe")
	format := decFlags.String("f", "text", "Format specifier")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			err := g.PrintAllWithFormat(*format)
			if err != nil {
				err = fmt.Errorf("Unable to print file contents: %v", err)
			}

			return err

		}, &safeName, false, c.client,
	)
}

// GetCommand decrypts and searches in a file and writes the result to stdout
func (c *CmdContext) GetCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman get", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File holding password safe")
	key := decFlags.String("k", "", "Key to search")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			err = g.PrintEntry(*key)
			if err != nil {
				return err
			}

			return nil

		}, &safeName, false, c.client,
	)
}

// DeleteCommand deletes an entry from a file
func (c *CmdContext) DeleteCommand(args []string) error {
	decFlags := flag.NewFlagSet("pwman del", flag.ContinueOnError)
	inFile := decFlags.String("i", "", "File holding password safe")
	key := decFlags.String("k", "", "Key to delete")

	err := decFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			return g.DeleteEntry(*key)
		}, &safeName, true, c.client,
	)
}

// BackupCommand allows to retrieve password data and stores it locally for backup purposes
func (c *CmdContext) BackupCommand(args []string) error {
	renFlags := flag.NewFlagSet("pwman bkp", flag.ContinueOnError)
	inFile := renFlags.String("i", "", "File holding password safe")
	outFile := renFlags.String("o", "", "File to store backup")

	err := renFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	outName := getBackupFileName(outFile)

	if outName == "" {
		return fmt.Errorf("No output file specified")
	}

	man := c.jotsManagerCreator(safeName)

	data, err := man.GetRawData(safeName)
	if err != nil {
		return fmt.Errorf("Unable to create backup: %v", err)
	}

	err = os.WriteFile(outName, data, 0o600)
	if err != nil {
		return fmt.Errorf("Unable to create backup: %v", err)
	}

	return nil
}

// RenameCommand allows to rename an existing entry
func (c *CmdContext) RenameCommand(args []string) error {
	renFlags := flag.NewFlagSet("pwman ren", flag.ContinueOnError)
	inFile := renFlags.String("i", "", "File holding password safe")
	key := renFlags.String("k", "", "Key of entry to rename")
	newKey := renFlags.String("n", "", "New key to use for entry")

	err := renFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	if *newKey == "" {
		return fmt.Errorf("No new key specified")
	}

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			return g.RenameEntry(*key, *newKey)

		}, &safeName, true, c.client,
	)
}

// UpsertCommand adds/modifies an entry in a file
func (c *CmdContext) UpsertCommand(args []string) error {
	putFlags := flag.NewFlagSet("pwman put", flag.ContinueOnError)
	inFile := putFlags.String("i", "", "File holding password safe")
	key := putFlags.String("k", "", "Key of entry to modify")
	dataFile := putFlags.String("v", "", "File containing value to associate with path/name")

	err := putFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
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

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			entryReplaced, err := g.UpsertEntry(*key, string(rawValue))
			if err != nil {
				return err
			}

			if entryReplaced {
				fmt.Println("Entry replaced")
			} else {
				fmt.Println("Entry added")
			}

			return nil

		}, &safeName, true, c.client,
	)
}

func (c *CmdContext) GetVersion(args []string) error {
	fmt.Println(VersionInfo)
	return nil
}

func (c *CmdContext) ObfuscateWebDavPassword(args []string) error {
	obfFlags := flag.NewFlagSet("pwman obf", flag.ContinueOnError)
	userId := obfFlags.String("u", "", "WebDAV user id")

	err := obfFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	if *userId == "" {
		return fmt.Errorf("No user id specified")
	}

	password, err := GetSecurePasswordVerified(enterPwText, reenterPwText)
	if err != nil {
		return err
	}

	obf := fcrypt.NewObfuscator(fcrypt.ObfEnvVar, fcrypt.ObfConfig)
	err = obf.Obfuscate(*userId, password)
	if err != nil {
		return err
	}

	return nil
}

// ClipboardCommand adds/modifies an entry in a file through replacing its content by the current
// contents of the clipboard.
func (c *CmdContext) ClipboardCommand(args []string) error {
	putFlags := flag.NewFlagSet("pwman clp", flag.ContinueOnError)
	inFile := putFlags.String("i", "", "File holding password safe")
	key := putFlags.String("k", "", "Key of entry to modify")
	clipCommand := putFlags.String("c", "", "Command to execute in order to retrieve the clipboard contents")

	err := putFlags.Parse(args)
	if err != nil {
		os.Exit(42)
	}

	safeName := getPwSafeFileName(inFile)

	if safeName == "" {
		return fmt.Errorf("No input file specified")
	}

	if *key == "" {
		return fmt.Errorf("No key specified")
	}

	clipCall := getClipboardCommand(clipCommand)

	if clipCall == "" {
		return fmt.Errorf("No command for retrieving clipboard spcecified")
	}

	cliParams := strings.Split(clipCall, " ")
	cmd := exec.Command(cliParams[0], cliParams[1:]...)

	outData, err := cmd.Output()
	if err != nil {
		fmt.Printf("Could not run command: %v", err)
		return err
	}

	rawValue := string(outData)

	man := c.jotsManagerCreator(safeName)

	return transact(man,
		func(g fcrypt.Gjotser) error {
			entryReplaced, err := g.UpsertEntry(*key, string(rawValue))
			if err != nil {
				return err
			}

			if entryReplaced {
				fmt.Println("Entry replaced")
			} else {
				fmt.Println("Entry added")
			}

			return nil

		}, &safeName, true, c.client,
	)
}

func main() {
	if v := os.Getenv("PWMANCIPHER"); v != "" {
		if v == "AES192" {
			fcrypt.AeadGenerator = fcrypt.GenAes192Gcm
		} else {
			fcrypt.AeadGenerator = fcrypt.GenChaCha20Poly1305
		}
	}

	subcommParser := NewSubcommandParser()
	ctx := NewContext()

	subcommParser.AddCommand("enc", ctx.EncryptCommand, "Encrypts a file")
	subcommParser.AddCommand("dec", ctx.DecryptCommand, "Decrypts a file")
	subcommParser.AddCommand("list", ctx.ListCommand, "Lists keys of entries in a file")
	subcommParser.AddCommand("get", ctx.GetCommand, "Get an entry from a file")
	subcommParser.AddCommand("put", ctx.UpsertCommand, "Adds/modifies an entry by setting its contents through a file")
	subcommParser.AddCommand("ren", ctx.RenameCommand, "Renames an entry in a file")
	subcommParser.AddCommand("del", ctx.DeleteCommand, "Deletes an entry from a file")
	subcommParser.AddCommand("pwd", ctx.PwdCommand, "Checks the password and transfers it to pwserv")
	subcommParser.AddCommand("rst", ctx.ResetCommand, "Deletes the password from pwserv")
	subcommParser.AddCommand("init", ctx.InitCommand, "Creates an empty password safe")
	subcommParser.AddCommand("clp", ctx.ClipboardCommand, "Adds/modifies an entry by setting its contents through the clipboard")
	subcommParser.AddCommand("ver", ctx.GetVersion, "Print version information")
	subcommParser.AddCommand("obf", ctx.ObfuscateWebDavPassword, "Obfuscate WebDAV password and create corresponding config")
	subcommParser.AddCommand("all", ctx.PrintAllCommand, "Print whole file contents in plaintext")
	subcommParser.AddCommand("bkp", ctx.BackupCommand, "Store a backup of the given password safe")

	subcommParser.Execute()
}
