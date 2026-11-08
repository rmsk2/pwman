package main

import (
	"testing"
)

func TestQrRegEx(t *testing.T) {
	url := "otpauth://diesisteintest"

	res, err := extractQrCode(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != "otpauth://diesisteintest" {
		t.Fatalf("Wrong text: %s", res)
	}
}

func TestQrRegExUppercase(t *testing.T) {
	url := "OTPAUTH://diesisteintest"

	res, err := extractQrCode(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != url {
		t.Fatalf("Wrong text: %s", res)
	}
}

func TestQrRegExEmpty(t *testing.T) {
	url := ""

	_, err := extractQrCode(url)
	if err == nil {
		t.Fatal("Empty string is no otpauth URL")
	}
}

func TestQrRegExConcatenated(t *testing.T) {
	url := "otpauth://diesisteintestotpauth://diesisteintest"

	_, err := extractQrCode(url)
	if err == nil {
		t.Fatal("Two unseparable are not detected")
	}
}

func TestQrRegExWhiteSpaceOnly(t *testing.T) {
	url := "              \n                    "

	_, err := extractQrCode(url)
	if err == nil {
		t.Fatal("Whitespace string is no otpauth URL")
	}
}

func TestQrRegExEmbedded(t *testing.T) {
	url := `Dies ist egal otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30 und danach kommt auch noch was`

	res, err := extractQrCode(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != `otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30` {
		t.Fatalf("Wrong URL matched: %s", res)
	}
}

func TestQrRegExEmbeddedMultiLine(t *testing.T) {
	url := "Dies ist egal\n prefix otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30\nund danach kommt auch noch was"

	res, err := extractQrCode(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != `otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30` {
		t.Fatalf("Wrong URL matched: %s", res)
	}
}

func TestQrRegExEmbeddedMultiLineCRLF(t *testing.T) {
	url := "Dies ist egal\r\n prefix otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30\r\nund danach kommt auch noch was"

	res, err := extractQrCode(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != `otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30` {
		t.Fatalf("Wrong URL matched: %s", res)
	}
}

func TestQrRegExMultipleSameLine(t *testing.T) {
	url := "otpauth://diesisteintest otpauth://diesisteintest2"

	res, err := extractQrCode(url)
	if err == nil {
		t.Log(res)
		t.Fatal("Multiple otpauth URLs not detected")
	}

	t.Log(err)
}

func TestQrRegExMultipleDifferentLine(t *testing.T) {
	url := "otpauth://diesisteintest\notpauth://diesisteintest2"

	_, err := extractQrCode(url)
	if err == nil {
		t.Fatal("Multiple otpauth URLs not detected")
	}

	t.Log(err)
}
