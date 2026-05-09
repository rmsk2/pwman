package pwsrvbase

import (
	"fmt"
	"testing"
)

func doBasicTest(storer PwStorer) error {
	err := storer.SetPassword("dummykey", "dummyvalue")
	if err != nil {
		return err
	}

	val, err := storer.GetPassword("dummykey")
	if err != nil {
		return err
	}

	if val != "dummyvalue" {
		return fmt.Errorf("Unexpected: %s", val)
	}

	err = storer.ResetPassword("dummykey")
	if err != nil {
		return err
	}

	val, err = storer.GetPassword("dummykey")
	if err == nil {
		return fmt.Errorf("Unexpected. Getting password should not have worked any longer. Value returned: %s", val)
	}

	return nil
}

func TestGeneric(t *testing.T) {
	s := NewGenericStorer()

	err := doBasicTest(s)
	if err != nil {
		t.Fatalf("Testing generic storer failed: %v", err)
	}
}

func TestObfuscating(t *testing.T) {
	s := NewObfuscatingStorer()

	err := doBasicTest(s)
	if err != nil {
		t.Fatalf("Testing obfuscating storer failed: %v", err)
	}
}
