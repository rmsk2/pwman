package pwsrvbase

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"pwman/fcrypt"
	"sync"
)

// PwStorer is an interface for a remote password storage
type PwStorer interface {
	SetPassword(name string, password string) error
	GetPassword(name string) (string, error)
	ResetPassword(name string) error
}

// GenericStorer imlpements the simplest possible in memory backend
type GenericStorer struct {
	mutex     *sync.Mutex
	passwords map[string]string
}

// NewGenericStorer returns an initialized GenercStorer sruct
func NewGenericStorer() *GenericStorer {
	return &GenericStorer{
		mutex:     new(sync.Mutex),
		passwords: map[string]string{},
	}
}

// SetPassword sets a password for a specified name
func (g *GenericStorer) SetPassword(name string, password string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.passwords[name] = password

	return nil
}

// GetPassword retrieves a password for a specified name
func (g *GenericStorer) GetPassword(name string) (string, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	password, ok := g.passwords[name]
	if !ok {
		return "", fmt.Errorf("Password %s unknown", name)
	}

	return password, nil
}

// ResetPassword deletes a password for a specified name
func (g *GenericStorer) ResetPassword(name string) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	delete(g.passwords, name)

	return nil
}

type ObfuscatingStorer struct {
	mutex     *sync.Mutex
	passwords map[string][]byte
	obfKey    []byte
}

func NewObfuscatingStorer() *ObfuscatingStorer {
	key := make([]byte, 16)

	_, err := rand.Read(key)
	if err != nil {
		panic("Unable to create obfuscation key")
	}

	return &ObfuscatingStorer{
		mutex:     new(sync.Mutex),
		passwords: map[string][]byte{},
		obfKey:    key,
	}
}

// SetPassword sets a password for a specified name
func (o *ObfuscatingStorer) SetPassword(name string, password string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	hash := sha256.Sum256([]byte(name))
	iv := hash[:16]
	obf := fcrypt.NewAes128CfbCryptor(o.obfKey, iv)

	data := make([]byte, len([]byte(password)))
	copy(data, password)
	obf.Process(data, obf.EncryptByte)

	o.passwords[name] = data

	return nil
}

// GetPassword retrieves a password for a specified name
func (o *ObfuscatingStorer) GetPassword(name string) (string, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	hash := sha256.Sum256([]byte(name))
	iv := hash[:16]
	obf := fcrypt.NewAes128CfbCryptor(o.obfKey, iv)

	raw, ok := o.passwords[name]
	if !ok {
		return "", fmt.Errorf("Password %s unknown", name)
	}

	data := make([]byte, len(raw))
	copy(data, raw)
	obf.Process(data, obf.DecryptByte)

	return string(data), nil
}

// ResetPassword deletes a password for a specified name
func (o *ObfuscatingStorer) ResetPassword(name string) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	delete(o.passwords, name)

	return nil
}
