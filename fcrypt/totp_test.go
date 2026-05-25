package fcrypt

import (
	"bytes"
	"testing"
	"time"
)

type totpTestCase struct {
	ts       int64
	expected string
}

func totpAt(t *TotpParams, unixTime int64) string {
	code, _ := t.GetCurrentCode(time.Unix(unixTime, 0))
	return code
}

// base32 of "12345678901234567890" without padding
const secretSha1B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestNewFromTotpUrlErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"no otpauth URL", "some random text without a url"},
		{"two URLs", "otpauth://totp/A?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ otpauth://totp/B?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		{"missing secret", "otpauth://totp/Example?algorithm=SHA1"},
		{"invalid base32 secret", "otpauth://totp/Example?secret=!!!"},
		{"empty base32 secret", "otpauth://totp/Example?secret=&period=30"},
		{"unknown algorithm", "otpauth://totp/Example?secret=" + secretSha1B32 + "&algorithm=MD5"},
		{"digits too small", "otpauth://totp/Example?secret=" + secretSha1B32 + "&digits=5"},
		{"digits too large", "otpauth://totp/Example?secret=" + secretSha1B32 + "&digits=9"},
		{"period too small", "otpauth://totp/Example?secret=" + secretSha1B32 + "&period=1"},
		{"period too large", "otpauth://totp/Example?secret=" + secretSha1B32 + "&period=61"},
	}

	for _, c := range cases {
		_, err := NewFromTotpUrl(c.input)
		if err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestNewFromTotpUrlDefaults(t *testing.T) {
	p, err := NewFromTotpUrl("otpauth://totp/Example?secret=" + secretSha1B32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.algo != Sha1 {
		t.Errorf("algo: got %v, want Sha1", p.algo)
	}
	if p.digits != 6 {
		t.Errorf("digits: got %d, want 6", p.digits)
	}
	if p.period != 30 {
		t.Errorf("period: got %d, want 30", p.period)
	}
	if !bytes.Equal(p.secret, []byte("12345678901234567890")) {
		t.Errorf("secret: got %v, want %v", p.secret, []byte("12345678901234567890"))
	}
}

func TestNewFromTotpUrlAllParams(t *testing.T) {
	url := "otpauth://totp/Example?secret=" + secretSha1B32 + "&algorithm=SHA256&digits=8&period=60"
	p, err := NewFromTotpUrl(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.algo != Sha256 {
		t.Errorf("algo: got %v, want Sha256", p.algo)
	}
	if p.digits != 8 {
		t.Errorf("digits: got %d, want 8", p.digits)
	}
	if p.period != 60 {
		t.Errorf("period: got %d, want 60", p.period)
	}
}

func TestNewFromTotpUrlEmbeddedInText(t *testing.T) {
	text := "some notes\notpauth://totp/Example?secret=" + secretSha1B32 + "\nmore notes"
	_, err := NewFromTotpUrl(text)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTotpRfc6238Sha1(t *testing.T) {
	p := NewTotpParams()
	p.algo = Sha1
	p.secret = []byte("12345678901234567890")
	p.digits = 8

	cases := []totpTestCase{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, c := range cases {
		if got := totpAt(p, c.ts); got != c.expected {
			t.Errorf("SHA1 ts=%d: got %s, want %s", c.ts, got, c.expected)
		}
	}
}

func TestTotpRfc6238Sha256(t *testing.T) {
	p := NewTotpParams()
	p.algo = Sha256
	p.secret = []byte("12345678901234567890123456789012")
	p.digits = 8

	cases := []totpTestCase{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	for _, c := range cases {
		if got := totpAt(p, c.ts); got != c.expected {
			t.Errorf("SHA256 ts=%d: got %s, want %s", c.ts, got, c.expected)
		}
	}
}

func TestTotpRfc6238Sha512(t *testing.T) {
	p := NewTotpParams()
	p.algo = Sha512
	p.secret = []byte("1234567890123456789012345678901234567890123456789012345678901234")
	p.digits = 8

	cases := []totpTestCase{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
		{20000000000, "47863826"},
	}

	for _, c := range cases {
		if got := totpAt(p, c.ts); got != c.expected {
			t.Errorf("SHA512 ts=%d: got %s, want %s", c.ts, got, c.expected)
		}
	}
}
