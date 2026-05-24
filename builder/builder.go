package main

import (
	"crypto/rand"
	"fmt"
	"os"
)

const bufSize = 32

func main() {
	buf := make([]byte, bufSize)
	// According to the documentation this can not fail. If generating
	// random number should fail the docu says the program "crashes irrevocably".
	_, _ = rand.Read(buf)

	if len(os.Args) < 2 {
		panic("No file name given")
	}

	f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "package main\n\n")
	if err != nil {
		panic(err)
	}

	_, err = fmt.Fprintf(f, "var obfuscator []byte = []byte {\n    ")
	if err != nil {
		panic(err)
	}

	for j := range bufSize {
		_, err = fmt.Fprintf(f, "0x%02x, ", buf[j])
		if err != nil {
			panic(err)
		}
	}
	_, err = fmt.Fprintf(f, "\n}\n")
	if err != nil {
		panic(err)
	}
}
