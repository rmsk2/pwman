package pwsrvbase

import (
	"fmt"
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
