package fcrypt

import (
	"crypto/rand"
	"math"
	"math/big"
	"strings"
)

const Base64 string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#!"
const Hex string = "abcdef0123456789"
const Numeric string = "0123456789"

var DefaultEntropy uint = 96

type PwGenerator struct {
	alphabet []rune
	pwLen    uint16
}

func NewBase64Generator() *PwGenerator {
	h := NewPwGenerator(Base64, 10)
	h.SetPwLengthByEntropy(DefaultEntropy)

	return h
}

func NewHexGenerator() *PwGenerator {
	h := NewPwGenerator(Hex, 10)
	h.SetPwLengthByEntropy(DefaultEntropy)

	return h
}

func NewNumericGenerator() *PwGenerator {
	h := NewPwGenerator(Numeric, 10)
	h.SetPwLengthByEntropy(DefaultEntropy)

	return h
}

func NewPwGenerator(a string, l uint16) *PwGenerator {
	return &PwGenerator{
		alphabet: []rune(a),
		pwLen:    l,
	}
}

func (p *PwGenerator) SetPwLength(desiredLength uint16) {
	p.pwLen = desiredLength
}

func (p *PwGenerator) SetPwLengthByEntropy(desiredEntropy uint) {
	entropyByCharacter := math.Log2(float64(len(p.alphabet)))

	p.pwLen = uint16(math.Ceil(float64(desiredEntropy) / entropyByCharacter))
}

func (p *PwGenerator) Entropy() float64 {
	return math.Log2(float64(len(p.alphabet))) * float64(p.pwLen)
}

func (p *PwGenerator) Generate() string {
	var b strings.Builder

	for i := 0; i < int(p.pwLen); i++ {
		// Int cannot return an error when using rand.Reader.
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(p.alphabet))))
		b.WriteRune(p.alphabet[index.Int64()])
	}

	return b.String()
}
