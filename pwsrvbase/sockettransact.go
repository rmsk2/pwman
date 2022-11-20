package pwsrvbase

import (
	"net"
	"strconv"
)

// NewSocketTransactor returns a transactorfunc that connects via tcp
func NewSocketTransactor(port uint16) TransActFunc {
	f := func(request *PwRequest) (string, error) {
		portStr := strconv.FormatUint(uint64(port), 10)
		portSpec := net.JoinHostPort("localhost", portStr)

		conn, err := net.Dial("tcp", portSpec)
		if err != nil {
			return "", err
		}
		defer func() { conn.Close() }()

		return ProcessPwRequestClient(conn, conn, request)
	}

	return f
}
