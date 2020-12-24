package pwsrvbase

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
)

// PwServPort holds the default port for the socket server
const PwServPort = 4567

// PwUDS contains the default UDS file name pattern for pwserv
const PwUDS = "/tmp/%s.pwman"

// ParamPrepareFunc are functions that know how determine parameters for the Listen function
type ParamPrepareFunc func() (string, string, error)

func doStop(c chan bool) bool {
	result := false

	select {
	case _, ok := <-c:
		if !ok {
			result = true
		}
	default:
	}

	return result
}

// MakeUDSAddress returns the UDS address to use for the current user
func MakeUDSAddress() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf(PwUDS, user.Name)
}

// NewTCPPrepareFunc returns a function that determines the connection parameters for
// a TCP connection to localhost
func NewTCPPrepareFunc(port uint16) ParamPrepareFunc {
	f := func() (string, string, error) {
		portStr := strconv.FormatUint(uint64(port), 10)
		portSpec := net.JoinHostPort("localhost", portStr)

		return "tcp", portSpec, nil
	}

	return f
}

// NewUDSPrepareFunc returns a function that determines the connection parameters for
// a connection via UNIX Domain sockets
func NewUDSPrepareFunc() ParamPrepareFunc {
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

// PwStoreSocket holds the password data
type PwStoreSocket struct {
	backend PwStorer
}

// NewSocketPwStore returns a pointer to an initialized PwStoreSocket struct
func NewSocketPwStore() *PwStoreSocket {
	return &PwStoreSocket{
		backend: NewGenericStorer(),
	}
}

func (p *PwStoreSocket) handleConnection(conn net.Conn) error {
	defer func() { conn.Close() }()

	return ProcessPwRequestServer(conn, conn, p.backend)
}

// Serve implements a socket listener for the JSON protocol
func (p *PwStoreSocket) Serve(prepare ParamPrepareFunc) {
	network, address, err := prepare()
	if err != nil {
		log.Println(err)
		return
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		log.Println(err)
		return
	}

	c := make(chan bool, 1)

	go func() {
		for !doStop(c) {
			conn, err := ln.Accept()
			if err != nil {
				if !doStop(c) {
					log.Println(err)
				}
				continue
			}

			err = p.handleConnection(conn)
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
	_ = <-sigc
	close(c)
	ln.Close()
	os.Exit(0)
}
