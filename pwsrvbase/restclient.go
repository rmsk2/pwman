package pwsrvbase

import (
	"bellonet/util"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"
)

// APIURL contains the base URL of the API
const APIURL = "/api/pwserv/data/" // POST to set password for purpose, GET to get password

// PwServPort contains the server port for the API
const PwServPort = 5678

// PwAPIClient contains the necessary information for a client of the pwserv API
type PwAPIClient struct {
	port uint16
}

// NewRESTClient returns an initialized pwAPIClient
func NewRESTClient(port uint16) *PwAPIClient {
	return &PwAPIClient{
		port: port,
	}
}

func (p *PwAPIClient) makeURL(name string) string {
	portStr := strconv.FormatUint(uint64(p.port), 10)
	portSpec := net.JoinHostPort("localhost", portStr)
	url := fmt.Sprintf("http://%s%s%s", portSpec, APIURL, name)

	return url
}

// SetPassword sets the password in pwserv
func (p *PwAPIClient) SetPassword(name string, password string) error {
	url := p.makeURL(name)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(password)))
	if err != nil {
		return err
	}

	_, err = DoHTTPRequest(req)
	if err != nil {
		return err
	}

	return nil
}

// GetPassword retrieves the password from  pwserv
func (p *PwAPIClient) GetPassword(name string) (string, error) {
	url := p.makeURL(name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	data, err := util.DoHTTPRequest(req)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ResetPassword deletes the apssword form pwserv
func (p *PwAPIClient) ResetPassword(name string) error {
	url := p.makeURL(name)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	_, err = util.DoHTTPRequest(req)
	if err != nil {
		return err
	}

	return nil
}

// DoHTTPRequest performs an HTTP request and returns the data returned by the server
func DoHTTPRequest(req *http.Request) ([]byte, error) {
	timeout := time.Duration(60 * time.Second)
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if 200 != resp.StatusCode {
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, resp.Status)
	}

	return body, nil
}
