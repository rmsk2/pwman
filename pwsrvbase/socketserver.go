package pwsrvbase

import (
	"log"
	"net"
	"os"
	"strconv"
)

// PwServPort holds the default port for the socket server
const PwServPort = 4567

// PwUDS contains the default UDS file name for pwserv
const PwUDS = "/tmp/martin.pwman"

// ParamPrepareFunc are functions that know how determine parameters for the Listen function
type ParamPrepareFunc func() (string, string, error)

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

// PwStoreSocket holds the password data
type PwStoreSocket struct {
	backend PwStorer
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
// connection via UNIX Domain sockets
func NewUDSPrepareFunc(fileName string) ParamPrepareFunc {
	f := func() (string, string, error) {
		err := os.RemoveAll(fileName)
		if err != nil {
			return "", "", err
		}

		return "unix", fileName, nil
	}

	return f
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
	defer func() { ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
		}

		err = p.handleConnection(conn)
		if err != nil {
			log.Println(err)
		}
	}
}
