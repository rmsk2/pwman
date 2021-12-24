package fcrypt

import (
	"bytes"
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
