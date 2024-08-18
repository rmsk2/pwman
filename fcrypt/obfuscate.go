package fcrypt

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type Obfucator struct {
	envName  string
	confName string
	rePw     *regexp.Regexp
	reUser   *regexp.Regexp
}

func NewObfuscator(e, c string) *Obfucator {
	return &Obfucator{
		envName:  e,
		confName: c,
		rePw:     regexp.MustCompile("^.*webdav_pw.+##obfuscated##:([0-9A-Fa-f]+).*$"),
		reUser:   regexp.MustCompile("^.*webdav_user.+\"(.+)\".*$"),
	}
}

func (o *Obfucator) Obfuscate(password string) (string, error) {
	return "", nil
}

func (o *Obfucator) matchPassword(line string) []byte {
	matches := o.rePw.FindStringSubmatch(line)

	if matches == nil {
		return nil
	}

	obfData := matches[1]
	if len(obfData)%2 != 0 {
		return nil
	}

	res := make([]byte, hex.DecodedLen(len(obfData)))
	n, err := hex.Decode(res, []byte(obfData))
	if err != nil {
		return nil
	}

	return res[:n]
}

func (o *Obfucator) matchUser(line string) string {
	matches := o.reUser.FindStringSubmatch(line)

	if matches == nil {
		return ""
	}

	return matches[1]
}

func (o *Obfucator) readRustpwmanConf() (string, []byte, error) {
	uid := ""
	var password []byte = nil

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", nil, fmt.Errorf("Unable to deobfuscate WebDAV password: %v", err)
	}

	confPath := filepath.Join(homeDir, o.confName)

	rustpwmanConf, err := os.Open(confPath)
	if err != nil {
		return "", nil, fmt.Errorf("Unable to deobfuscate WebDAV password: %v", err)
	}
	defer rustpwmanConf.Close()

	scanner := bufio.NewScanner(rustpwmanConf)
	for scanner.Scan() {
		line := scanner.Text()

		if uid == "" {
			uid = o.matchUser(line)
		}

		if password == nil {
			password = o.matchPassword(line)
		}
	}

	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("Unable to deobfuscate WebDAV password: %v", err)
	}

	if (uid == "") || (password == nil) {
		return "", nil, fmt.Errorf("Unable to deobfuscate WebDAV password: Rustpwman config could not be parsed")
	}

	return uid, password, nil
}

func (o *Obfucator) DeObfuscate() (string, string, error) {
	obfString := os.Getenv(o.envName)

	if obfString == "" {
		return "", "", fmt.Errorf("Unable to deobfuscate WebDAV password: Environment variable '%s' not set", o.envName)
	}

	h := sha256.New()
	h.Write([]byte(obfString))
	raw := h.Sum(nil)

	cip := NewAes128CfbCryptor(raw[:16], raw[16:])

	userId, password, err := o.readRustpwmanConf()
	if err != nil {
		return "", "", err
	}

	cip.Process(password, cip.DecryptByte)
	pw := string(password)

	return userId, pw, nil
}

type aes128Cfb8Cryptor struct {
	aes   cipher.Block
	curIv []byte
}

func NewAes128CfbCryptor(key, iv []byte) *aes128Cfb8Cryptor {
	k := make([]byte, len(key))
	i := make([]byte, len(iv))

	copy(k, key)
	copy(i, iv)

	aes, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	return &aes128Cfb8Cryptor{
		aes:   aes,
		curIv: i,
	}
}

func (a *aes128Cfb8Cryptor) Process(data []byte, f func(byte) byte) {
	for i := 0; i < len(data); i++ {
		data[i] = f(data[i])
	}
}

func (a *aes128Cfb8Cryptor) DecryptByte(in byte) byte {
	r := make([]byte, 16)
	a.aes.Encrypt(r, a.curIv)
	o := in ^ r[0]

	for i := 0; i < 15; i++ {
		a.curIv[i] = a.curIv[i+1]
	}

	a.curIv[15] = in

	return o
}

func (a *aes128Cfb8Cryptor) EncryptByte(in byte) byte {
	r := make([]byte, 16)
	a.aes.Encrypt(r, a.curIv)
	o := in ^ r[0]

	for i := 0; i < 15; i++ {
		a.curIv[i] = a.curIv[i+1]
	}

	a.curIv[15] = o

	return o
}
