package pwsrvbase

import (
	"log"
	"net"
	"strconv"
)

// PwServPort holds the default port for the socket server
const PwServPort = 4567

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

// Serve implements a socket listener for the JSON protocol
func (p *PwStoreSocket) Serve(port uint16) {
	portStr := strconv.FormatUint(uint64(port), 10)
	portSpec := net.JoinHostPort("localhost", portStr)

	ln, err := net.Listen("tcp", portSpec)
	if err != nil {
		log.Println(err)
		return
	}

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
