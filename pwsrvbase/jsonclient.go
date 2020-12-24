package pwsrvbase

import (
	"net"
	"strconv"
)

// GenericJSONClient holds the context for a generic JSON client
type GenericJSONClient struct {
	port uint16
}

// NewGenericJSONClient returns an initalized GenerJSONClient struct
func NewGenericJSONClient(port uint16) *GenericJSONClient {
	return &GenericJSONClient{
		port: port,
	}
}

func (g *GenericJSONClient) transact(request *PwRequest) (string, error) {
	portStr := strconv.FormatUint(uint64(g.port), 10)
	portSpec := net.JoinHostPort("localhost", portStr)

	conn, err := net.Dial("tcp", portSpec)
	if err != nil {
		return "", err
	}
	defer func() { conn.Close() }()

	return ProcessPwRequestClient(conn, conn, request)
}

// SetPassword sets a password for a specified name
func (g *GenericJSONClient) SetPassword(name string, password string) error {
	request := &PwRequest{
		Command: CommandSet,
		PwName:  name,
		PwData:  password,
	}

	_, err := g.transact(request)

	return err
}

// GetPassword retrieves a password for a specified name
func (g *GenericJSONClient) GetPassword(name string) (string, error) {
	request := &PwRequest{
		Command: CommandGet,
		PwName:  name,
		PwData:  "",
	}

	return g.transact(request)
}

// ResetPassword deletes a password for a specified name
func (g *GenericJSONClient) ResetPassword(name string) error {
	request := &PwRequest{
		Command: CommandReset,
		PwName:  name,
		PwData:  "",
	}

	_, err := g.transact(request)

	return err
}
