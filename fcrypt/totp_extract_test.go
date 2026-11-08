package fcrypt

import (
	"testing"
)

func TestQrRegEx(t *testing.T) {
	url := "otpauth://totp/diesisteintest"

	res, err := ExtractTotpUrl(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != "otpauth://totp/diesisteintest" {
		t.Fatalf("Wrong text: %s", res)
	}
}

func TestQrRegExUppercase(t *testing.T) {
	url := "OTPAUTH://TOTP/diesisteintest"

	res, err := ExtractTotpUrl(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != url {
		t.Fatalf("Wrong text: %s", res)
	}
}

func TestQrRegExEmpty(t *testing.T) {
	url := ""

	_, err := ExtractTotpUrl(url)
	if err == nil {
		t.Fatal("Empty string is no otpauth URL")
	}
}

func TestQrRegExNoUrl(t *testing.T) {
	url := "In diesem Text gibt es keine passende otpauth URL\nAuch nicht in der zweiten Zeile\n"

	_, err := ExtractTotpUrl(url)
	if err == nil {
		t.Fatal("Empty string is no otpauth URL")
	}
}

func TestQrRegExConcatenated(t *testing.T) {
	url := "otpauth://totp/diesisteintestotpauth://totp/diesisteintest"

	_, err := ExtractTotpUrl(url)
	if err == nil {
		t.Fatal("Two unseparable are not detected")
	}
}

func TestQrRegExWhiteSpaceOnly(t *testing.T) {
	url := "              \n                    "

	_, err := ExtractTotpUrl(url)
	if err == nil {
		t.Fatal("Whitespace string is no otpauth URL")
	}
}

func TestQrRegExEmbedded(t *testing.T) {
	url := `Dies ist egal otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30 und danach kommt auch noch was`

	res, err := ExtractTotpUrl(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != `otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30` {
		t.Fatalf("Wrong URL matched: %s", res)
	}
}

func TestQrRegExEmbeddedMultiLine(t *testing.T) {
	url := "Dies ist egal\n prefix otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30\nund danach kommt auch noch was"

	res, err := ExtractTotpUrl(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != `otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30` {
		t.Fatalf("Wrong URL matched: %s", res)
	}
}

func TestQrRegExEmbeddedMultiLineCRLF(t *testing.T) {
	url := "Dies ist egal\r\n prefix otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30\r\nund danach kommt auch noch was"

	res, err := ExtractTotpUrl(url)
	if err != nil {
		t.Fatal(err)
	}

	if res != `otpauth://totp/account%20test?secret=AAAAAAAAAAAAAAAA&digits=6&period=30` {
		t.Fatalf("Wrong URL matched: %s", res)
	}
}

func TestQrRegExMultipleSameLine(t *testing.T) {
	url := "otpauth://totp/diesisteintest otpauth://totp/diesisteintest2"

	res, err := ExtractTotpUrl(url)
	if err == nil {
		t.Log(res)
		t.Fatal("Multiple otpauth URLs not detected")
	}

	t.Log(err)
}

func TestQrRegExMultipleDifferentLine(t *testing.T) {
	url := "otpauth://totp/diesisteintest\notpauth://totp/diesisteintest2"

	_, err := ExtractTotpUrl(url)
	if err == nil {
		t.Fatal("Multiple otpauth URLs not detected")
	}

	t.Log(err)
}
