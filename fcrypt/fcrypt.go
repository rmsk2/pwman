// Package fcrypt handles the low level crypto stuff
package fcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const ObfEnvVar = "RUSTPWMAN_OBFUSCATION"
const ObfConfig = ".rustpwman"

type AeadGen func(key []byte) (cipher.AEAD, error)

var AeadGenerator AeadGen = GenAes256Gcm

func GenAes256Gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct AES-256 object: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct an AES-256 GCM object: %v", err)
	}

	return aesGCM, nil
}

func GenAes192Gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[0:24])
	if err != nil {
		return nil, fmt.Errorf("Unable to construct AES-192 object: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct an AES-192 GCM object: %v", err)
	}

	return aesGCM, nil
}

func GenChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// Gjotser describes a thing that is in essence an encrypted key value store
type Gjotser interface {
	PrintKeyList() error
	PrintEntry(key string) error
	GetKeyList() ([]string, error)
	GetEntry(key string) (string, error)
	DeleteEntry(key string) error
	RenameEntry(key string, newKey string) error
	UpsertEntry(key string, data string) (bool, error)
}

type GjotsManager interface {
	Open(inFile string, password string) (Gjotser, error)
	GetRawData(inFile string) ([]byte, error)
	Init(pbkdfId string) (Gjotser, error)
	Close(fileName string, password string) error
}

func GetGjotsManager(name string) GjotsManager {
	var res GjotsManager

	if strings.HasPrefix(name, "https://") {
		deobfuscator := NewObfuscator(ObfEnvVar, ObfConfig)
		res = NewGjotsWebdav(NewWebDavHelper(), deobfuscator.DeObfuscate)
	} else {
		res = NewJotsFileManager()
	}

	return res
}

// KeyDeriveFunc is function that knows how to create an AES-256 key from a salt and a password
type KeyDeriveFunc func(password *string, salt []byte) (key []byte, err error)

// PbKdfSha256 denotes a simple password hashing algorithm
const PbKdfSha256 = "sha256"

// PbKdfArgon2id denotes the Argon2Id password algorithm
const PbKdfArgon2id = "argon2"

// PbKdfScrypt denotes the Scrypt password algorithm
const PbKdfScrypt = "scrypt"

// DefaultSaltLength denotes the length of the salt generated by GenKey
var DefaultSaltLength uint = 16

// GenKey derives a session key from a password and a salt value. Both are returned
func GenKey(password *string, reGenKey KeyDeriveFunc) (salt []byte, key []byte, err error) {
	salt = make([]byte, DefaultSaltLength)

	_, err = rand.Read(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to generate salt for key: %v", err)
	}

	key, err = reGenKey(password, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to generate key: %v", err)
	}

	return salt, key, nil
}

func makePasswordHasher(id string) (KeyDeriveFunc, error) {
	switch id {
	case PbKdfSha256:
		return SHA256KeyGen, nil
	case PbKdfArgon2id:
		return Argon2KeyGen, nil
	case PbKdfScrypt:
		return ScryptKeyGen, nil
	default:
		return nil, fmt.Errorf("Key derivation function '%s' unknown", id)
	}
}

// Argon2KeyGen regenerates a key from a password and a salt using Argon2
func Argon2KeyGen(password *string, salt []byte) (key []byte, err error) {
	key = argon2.IDKey([]byte(*password), salt, 2, 15*1024, 1, 32)

	return key, nil
}

// ScryptKeyGen regenerates a key from a password and a salt using scrypt
func ScryptKeyGen(password *string, salt []byte) (key []byte, err error) {
	key, err = scrypt.Key([]byte(*password), salt, 32768, 8, 2, 32)

	return key, err
}

// SHA256KeyGen regenerates a key from a password and a salt using a simple algorithm
func SHA256KeyGen(password *string, salt []byte) (key []byte, err error) {
	hash := sha256.New()
	keyBytes := ([]byte)(*password)

	_, err = hash.Write(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to regenerate key: %v", err)
	}

	_, err = hash.Write(salt)
	if err != nil {
		return nil, fmt.Errorf("Unable to regenerate key: %v", err)
	}

	_, err = hash.Write(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to regenerate key: %v", err)
	}

	key = hash.Sum(nil)

	return key, nil
}

// PwDataMetaInfo contains the meta information of an encrypted data structure
type PwDataMetaInfo struct {
	PbKdf string
	Salt  []byte
	Nonce []byte
	Data  []byte
}

func makePWDataMetaInfo(kdfId string) *PwDataMetaInfo {
	return &PwDataMetaInfo{
		PbKdf: kdfId,
		Salt:  []byte{},
		Nonce: []byte{},
		Data:  []byte{},
	}
}

func makePWDataMetaInfoEmpty() *PwDataMetaInfo {
	return &PwDataMetaInfo{
		PbKdf: "",
		Salt:  []byte{},
		Nonce: []byte{},
		Data:  []byte{},
	}
}

// EncryptBytes returns the data bytes in encrypted form
func EncryptBytes(password *string, data []byte, kdfId string) (encryptedBytes []byte, err error) {
	reGenKey, err := makePasswordHasher(kdfId)
	if err != nil {
		return nil, fmt.Errorf("Unable to perform pw based encryption: %v", err)
	}

	pwData := makePWDataMetaInfo(kdfId)

	salt, key, err := GenKey(password, reGenKey)
	if err != nil {
		return nil, fmt.Errorf("Unable to perform pw based encryption: %v", err)
	}

	aead, err := AeadGenerator(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to perform pw based encryption: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("Unable to perform pw based encryption: %v", err)
	}

	pwData.Salt = salt
	pwData.Nonce = nonce
	pwData.Data = aead.Seal(nil, nonce, data, nil)

	res, err := json.MarshalIndent(pwData, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("Unable to perform pw based encryption: %v", err)
	}

	return res, nil
}

func WriteEncData(data []byte, password string, w io.Writer, kdfId string) error {
	encBytes, err := EncryptBytes(&password, data, kdfId)
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	_, err = io.Copy(w, bytes.NewBuffer(encBytes))
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	return nil

}

// SaveEncData saves the specified data in encrypted form
func SaveEncData(data []byte, password string, fileName string, kdfId string) error {
	encBytes, err := EncryptBytes(&password, data, kdfId)
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	err = os.WriteFile(fileName, encBytes, 0600)
	if err != nil {
		return fmt.Errorf("Unable to encrypt file: %v", err)
	}

	return nil
}

func ReadEncData(password string, r io.Reader) ([]byte, string, error) {
	encBytes, err := io.ReadAll(r)
	if err != nil {
		return nil, "", fmt.Errorf("Error decrypting file: %v", err)
	}

	clearData, kdfId, err := DecryptBytes(&password, encBytes)
	if err != nil {
		return nil, "", fmt.Errorf("Error decrypting file: %v", err)
	}

	return clearData, kdfId, nil

}

// LoadEncData loads the specified data in encrypted form and returns its plaintext
func LoadEncData(password string, fileName string) ([]byte, string, error) {
	encBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, "", fmt.Errorf("Error decrypting file: %v", err)
	}

	clearData, kdfId, err := DecryptBytes(&password, encBytes)
	if err != nil {
		return nil, "", fmt.Errorf("Error decrypting file: %v", err)
	}

	return clearData, kdfId, nil
}

// DecryptBytes returns the data bytes in decrypted form
func DecryptBytes(password *string, encData []byte) (data []byte, pbKdfUsed string, err error) {
	pwData := makePWDataMetaInfoEmpty()

	err = json.Unmarshal(encData, pwData)
	if err != nil {
		return nil, "", fmt.Errorf("Unable to perform pw based decryption: %v", err)
	}

	salt := pwData.Salt
	nonce := pwData.Nonce
	dataEnc := pwData.Data
	pbKdfId := pwData.PbKdf

	reGenKey, err := makePasswordHasher(pbKdfId)
	if err != nil {
		return nil, "", fmt.Errorf("Unable to perform pw based decryption: %v", err)
	}

	key, err := reGenKey(password, salt)
	if err != nil {
		return nil, "", fmt.Errorf("Unable to perform pw based decryption: %v", err)
	}

	aead, err := AeadGenerator(key)
	if err != nil {
		return nil, "", fmt.Errorf("Unable to perform pw based encryption: %v", err)
	}

	data, err = aead.Open(nil, nonce, dataEnc, nil)
	if err != nil {
		return nil, "", fmt.Errorf("Unable to perform pw based decryption: %v", err)
	}

	return data, pbKdfId, nil
}
