package fcrypt

import (
	"bytes"
	"testing"
)

func Test1(t *testing.T) {
	password := ""

	key, salt, err := GenKey(&password)
	if err != nil {
		t.Fatal(err)
	}

	key2, salt2, err := GenKey(&password)
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

	enc, err := EncryptBytes(&password, data)
	if err != nil {
		t.Fatal(err)
	}

	plainAgain, err := DecryptBytes(&password, enc)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, plainAgain) {
		t.Fatal("Palintexts different")
	}
}

func Test3(t *testing.T) {
	password := "schnuppsi"
	data := ([]byte)("Dies ist ein toller Klartext")

	enc, err := EncryptBytes(&password, data)
	if err != nil {
		t.Fatal(err)
	}

	enc[len(enc)-1] = enc[len(enc)-1] ^ 1

	_, err = DecryptBytes(&password, enc)
	if err == nil {
		t.Fatal("Decryption should have failed")
	}
}
