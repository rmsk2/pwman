//go:build windows
// +build windows

// Package windomainsock implements the pwman functionality of unix domain sockets on Windows
package windomainsock

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"pwman/pwsrvbase"
)

// PwUDS contains the default UDS file name pattern for pwserv
const PwUDS = "pwman.sock"

// MakeUDSAddress returns the UDS address to use for the current user
func MakeUDSAddress() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	return filepath.Join(user.HomeDir, PwUDS)
}

// NewUDSTransactor returns a transactorfunc that connects via Unix domain sockets
func NewUDSTransactor() pwsrvbase.TransActFunc {
	f := func(request *pwsrvbase.PwRequest) (string, error) {
		fileName := MakeUDSAddress()
		conn, err := net.Dial("unix", fileName)
		if err != nil {
			return "", err
		}
		defer func() { conn.Close() }()

		return pwsrvbase.ProcessPwRequestClient(conn, conn, request)
	}

	return f
}

// NewUDSPrepareFunc returns a function that determines the connection parameters for
// a connection via UNIX Domain sockets
func NewUDSPrepareFunc() pwsrvbase.ParamPrepareFunc {
	f := func() (string, string, error) {
		fileName := MakeUDSAddress()
		err := os.RemoveAll(fileName)
		if err != nil {
			return "", "", err
		}

		return "unix", fileName, nil
	}

	return f
}
