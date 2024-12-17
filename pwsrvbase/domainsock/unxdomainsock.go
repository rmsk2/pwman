//go:build darwin || linux
// +build darwin linux

// Package domainsock implements communication through a UNIX domain socket on UNIX
package domainsock

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"pwman/pwsrvbase"
	"syscall"
)

// PwUDS contains the default UDS file name pattern for pwserv
const PwUDS = "/tmp/%s.pwman"

// MakeUDSAddress returns the UDS address to use for the current user
func MakeUDSAddress() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf(PwUDS, user.Username)
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

		// Only user may access newly generated files including the file
		// representing the UNIX Domain socket
		syscall.Umask(0077)

		return "unix", fileName, nil
	}

	return f
}
