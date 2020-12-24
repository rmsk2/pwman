package pwsrvbase

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

// CommandGet is the constant used for the Get command
const CommandGet = "GET"

// CommandSet is the constant used for the Set command
const CommandSet = "SET"

// CommandReset is the constant used for the Reset command
const CommandReset = "RST"

// ResultOK is returned if no error occurred
const ResultOK = 0

// ResultError is used if an (unspecified) error occurred
const ResultError = 1

// PwRequest is the struct used for requests
type PwRequest struct {
	Command string
	PwName  string
	PwData  string
}

// ReadRequest reads a request from the reader given
func ReadRequest(reader io.Reader) (*PwRequest, error) {
	data, err := readBlock(reader)
	if err != nil {
		return nil, fmt.Errorf("Unable to read request: %v", err)
	}

	result := new(PwRequest)
	err = json.Unmarshal(data, result)
	if err != nil {
		return nil, fmt.Errorf("Unable to read request: %v", err)
	}

	return result, nil
}

// WriteRequest writes a request to the writer specified
func WriteRequest(writer io.Writer, request *PwRequest) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("Unable to write request: %v", err)
	}

	err = writeBlock(data, writer)
	if err != nil {
		return fmt.Errorf("Unable to write request: %v", err)
	}

	return nil
}

// ReadResponse reads a response from the reader given
func ReadResponse(reader io.Reader) (*PwResponse, error) {
	data, err := readBlock(reader)
	if err != nil {
		return nil, fmt.Errorf("Unable to read request: %v", err)
	}

	result := new(PwResponse)
	err = json.Unmarshal(data, result)
	if err != nil {
		return nil, fmt.Errorf("Unable to read request: %v", err)
	}

	return result, nil
}

// WriteResponse writes a response to the writer specified
func WriteResponse(writer io.Writer, response *PwResponse) error {
	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("Unable to write request: %v", err)
	}

	err = writeBlock(data, writer)
	if err != nil {
		return fmt.Errorf("Unable to write request: %v", err)
	}

	return nil
}

// PwResponse holds the data needed for a response
type PwResponse struct {
	ResultCode int
	ResultData string
}

func readBlock(reader io.Reader) ([]byte, error) {
	buf := []byte{0, 0}
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}

	dataLen := binary.BigEndian.Uint16(buf)
	data := make([]byte, dataLen)

	_, err = io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func writeBlock(data []byte, writer io.Writer) error {
	if len(data) > 65535 {
		return fmt.Errorf("Data too big")
	}

	buf := []byte{0, 0}
	binary.BigEndian.PutUint16(buf, (uint16)(len(data)))

	_, err := io.Copy(writer, bytes.NewReader(buf))
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, bytes.NewReader(data))
	if err != nil {
		return err
	}

	return nil
}

// ProcessPwRequestServer reads a request and writes a response
func ProcessPwRequestServer(in io.Reader, out io.Writer, backend PwStorer) error {
	request, err := ReadRequest(in)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Unable to read request: %v", err)
	}

	response := new(PwResponse)

	setError := func() {
		response.ResultCode = ResultError
		response.ResultData = ""
	}

	switch request.Command {
	case CommandGet:
		password, err := backend.GetPassword(request.PwName)
		if err != nil {
			setError()
			log.Println(err)
		} else {
			response.ResultCode = ResultOK
			response.ResultData = password
		}
	case CommandSet:
		err := backend.SetPassword(request.PwName, request.PwData)
		if err != nil {
			setError()
			log.Println(err)
		} else {
			response.ResultCode = ResultOK
			response.ResultData = ""
		}
	case CommandReset:
		err := backend.ResetPassword(request.PwName)
		if err != nil {
			setError()
			log.Println(err)
		} else {
			response.ResultCode = ResultOK
			response.ResultData = ""
		}
	default:
		setError()
	}

	err = WriteResponse(out, response)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("Unable to write response: %v", err)
	}

	return nil
}

// ProcessPwRequestClient implements a client side transaction
func ProcessPwRequestClient(in io.Reader, out io.Writer, request *PwRequest) (string, error) {
	err := WriteRequest(out, request)
	if err != nil {
		return "", fmt.Errorf("Unable to send request: %v", err)
	}

	response, err := ReadResponse(in)
	if err != nil {
		return "", fmt.Errorf("Unable to retreive response: %v", err)
	}

	if response.ResultCode != ResultOK {
		return response.ResultData, fmt.Errorf("Server returned error %d", response.ResultCode)
	}

	return response.ResultData, nil
}
