package fcrypt

import (
	"crypto/sha256"
	"testing"
)

func TestEnDecryptCFB(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("This is a test key"))
	raw := h.Sum(nil)

	s := "This is a test plaintext"
	b := []byte(s)
	ref := s

	enc := NewAes128CfbCryptor(raw[:16], raw[16:])
	dec := NewAes128CfbCryptor(raw[:16], raw[16:])

	enc.Process(b, enc.EncryptByte)

	if string(b) == ref {
		t.Fatal("CFB-8 Encryption does not work")
	}

	dec.Process(b, dec.DecryptByte)

	if string(b) != ref {
		t.Fatal("CFB-8 Decryption does not work")
	}
}
