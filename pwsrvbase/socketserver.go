package pwsrvbase

import (
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

// PwServPort holds the default port for the socket server
const PwServPort = 4567

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

// PwStoreSocket holds the password data
type PwStoreSocket struct {
	backend PwStorer
}

// NewSocketPwStore returns a pointer to an initialized PwStoreSocket struct
func NewSocketPwStore(backend PwStorer) *PwStoreSocket {
	return &PwStoreSocket{
		backend: backend,
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

	// Handle shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
	_ = <-sigc
	// Make mainloop stop
	close(c)
	// Close server socket and make UDS disappear
	ln.Close()
	os.Exit(0)
}
