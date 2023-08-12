package fcrypt

import (
	"bytes"
	"fmt"
	"testing"
)

func Test1(t *testing.T) {
	password := ""

	key, salt, err := GenKey(&password, SHA256KeyGen)
	if err != nil {
		t.Fatal(err)
	}

	key2, salt2, err := GenKey(&password, SHA256KeyGen)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(key, key2) {
		t.Fatal("Keys should be different")
	}

	if bytes.Equal(salt, salt2) {
		t.Fatal("Salt values should be different")
	}
}

func Test2(t *testing.T) {
	password := "schnuppsi"
	data := ([]byte)("Dies ist ein toller Klartext")

	enc, err := EncryptBytes(&password, data, PbKdfSha256)
	if err != nil {
		t.Fatal(err)
	}

	plainAgain, kdfId, err := DecryptBytes(&password, enc)
	if err != nil {
		t.Fatal(err)
	}

	if kdfId != PbKdfSha256 {
		t.Fatal("Wrong KDF")
	}

	if !bytes.Equal(data, plainAgain) {
		t.Fatal("Plaintexts different")
	}
}

func Test3(t *testing.T) {
	password := "schnuppsi"
	data := ([]byte)("Dies ist ein toller Klartext")

	enc, err := EncryptBytes(&password, data, PbKdfSha256)
	if err != nil {
		t.Fatal(err)
	}

	enc[len(enc)-1] = enc[len(enc)-1] ^ 1

	_, _, err = DecryptBytes(&password, enc)
	if err == nil {
		t.Fatal("Decryption should have failed")
	}
}

func TestSha2KeyGen(t *testing.T) {
	salt := "0011223344556677"
	password := "Dies ist ein Test"

	key, err := SHA256KeyGen(&password, []byte(salt))
	if err != nil {
		t.Fatalf("SHA256 key derivation did not work: %v", err)
	}

	testVal := fmt.Sprintf("%x", key)
	if testVal != "8bbb8e596fdeb564b5ded3d60af1cf790a326309ada0045cc61d07fd982876d2" {
		t.Fatalf("Wrong key generated: %s", testVal)
	}
}
