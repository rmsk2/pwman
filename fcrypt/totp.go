package fcrypt

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type AlgoId uint

const (
	Sha1 = iota
	Sha256
	Sha512
)

type TotpParams struct {
	t0     int64
	secret []byte
	period int64
	digits int
	algo   AlgoId
}

func NewTotpParams() *TotpParams {
	return &TotpParams{
		t0:     0,
		secret: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		period: 30,
		digits: 6,
		algo:   Sha1,
	}
}

func NewFromTotpUrl(text string) (*TotpParams, error) {
	const prefix = "otpauth://totp/"

	first := strings.Index(text, prefix)
	if first == -1 {
		return nil, fmt.Errorf("no TOTP URL found")
	}

	if strings.Contains(text[first+len(prefix):], prefix) {
		return nil, fmt.Errorf("multiple TOTP URLs found")
	}

	end := strings.IndexFunc(text[first:], unicode.IsSpace)
	var rawURL string
	if end == -1 {
		rawURL = text[first:]
	} else {
		rawURL = text[first : first+end]
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid TOTP URL: %w", err)
	}

	p := NewTotpParams()
	q := u.Query()

	secret := q.Get("secret")
	if secret == "" {
		return nil, fmt.Errorf("TOTP URL missing secret parameter")
	}

	p.secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return nil, fmt.Errorf("invalid secret: %w", err)
	}

	if algo := q.Get("algorithm"); algo != "" {
		switch strings.ToUpper(algo) {
		case "SHA1":
			p.algo = Sha1
		case "SHA256":
			p.algo = Sha256
		case "SHA512":
			p.algo = Sha512
		default:
			return nil, fmt.Errorf("unknown algorithm: %s", algo)
		}
	}

	if digits := q.Get("digits"); digits != "" {
		digitsRaw, err := strconv.Atoi(digits)
		if err != nil {
			return nil, fmt.Errorf("invalid digits: %w", err)
		}

		if (digitsRaw < 6) || (digitsRaw > 8) {
			return nil, fmt.Errorf("invalid digits: %d", digitsRaw)
		}
		p.digits = digitsRaw
	}

	if period := q.Get("period"); period != "" {
		periodRaw, err := strconv.ParseInt(period, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid period: %w", err)
		}

		if (periodRaw < 2) || (periodRaw > 60) {
			return nil, fmt.Errorf("invalid perod: %d", periodRaw)
		}
		p.period = periodRaw
	}

	return p, nil
}

func (t *TotpParams) GetCurrentCode(currentTime time.Time) (string, int64) {
	code := ""
	secsRemaining := t.period - ((currentTime.Unix() - t.t0) % t.period)

	counter := (currentTime.Unix() - t.t0) / t.period
	raw := make([]byte, 8)
	binary.BigEndian.PutUint64(raw, (uint64)(counter))

	var h func() hash.Hash

	switch t.algo {
	case Sha1:
		h = sha1.New
	case Sha256:
		h = sha256.New
	default:
		h = sha512.New
	}

	totpHmac := hmac.New(h, t.secret)
	totpHmac.Write(raw)
	data := totpHmac.Sum(nil)

	index := (int32)(data[len(data)-1] & 0x0F)

	var totpInt int32 = (int32)(data[index]) & 0x7f
	var i int32

	for i = 1; i <= 3; i++ {
		totpInt = (totpInt << 8) | (int32)(data[i+index])
	}

	var modVal int32

	switch t.digits {
	case 6:
		modVal = 1000000
	case 7:
		modVal = 10000000
	default:
		modVal = 100000000
	}

	code = fmt.Sprintf("%0*d", t.digits, totpInt%modVal)

	return code, secsRemaining
}
