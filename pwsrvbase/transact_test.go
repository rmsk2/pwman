package pwsrvbase

import (
	"io"
	"testing"
)

type testResult struct {
	err    error
	result string
}

func serverWrapper(ready chan error, storer PwStorer, in io.Reader, out io.Writer) {
	err := ProcessPwRequestServer(in, out, storer)
	ready <- err
}

type testSetup struct {
	rs, rc     io.Reader
	ws, wc     io.Writer
	storer     PwStorer
	servReady  chan error
	servResult error
}

func (t *testSetup) transact(request *PwRequest) (string, error) {
	go serverWrapper(t.servReady, t.storer, t.rs, t.wc)
	result, clientErr := ProcessPwRequestClient(t.rc, t.ws, request)

	t.servResult = <-t.servReady

	return result, clientErr
}

func Test1(t *testing.T) {
	rs, ws := io.Pipe()
	defer func() { rs.Close(); ws.Close() }()
	rc, wc := io.Pipe()
	defer func() { rc.Close(); wc.Close() }()

	tst := &testSetup{
		rs:        rs,
		ws:        ws,
		rc:        rc,
		wc:        wc,
		servReady: make(chan error),
		storer:    NewGenericStorer(),
	}

	client := NewGenericJSONClient(tst.transact)

	clientErr := client.SetPassword("test", "Wurschtegal")

	if tst.servResult != nil {
		t.Fatal(tst.servResult)
	}

	if clientErr != nil {
		t.Fatal(clientErr)
	}

	result, clientErr := client.GetPassword("test")

	if tst.servResult != nil {
		t.Fatal(tst.servResult)
	}

	if clientErr != nil {
		t.Fatal(clientErr)
	}

	if result != "Wurschtegal" {
		t.Fatalf("Unexpected: '%s'", result)
	}

	clientErr = client.ResetPassword("test")

	if tst.servResult != nil {
		t.Fatal(tst.servResult)
	}

	if clientErr != nil {
		t.Fatal(clientErr)
	}

	result, clientErr = client.GetPassword("test")

	if tst.servResult != nil {
		t.Fatal(tst.servResult)
	}

	if clientErr == nil {
		t.Fatal("Should have failed!")
	}
}
