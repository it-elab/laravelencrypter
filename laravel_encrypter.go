package golaravelencrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wulijun/go-php-serialize/phpserialize"
	"strings"
)

type Encrypter interface {
	Encrypt(value string, serialize bool) (ciphertext string, err error)
	Decrypt(playload string, serialize bool) (plaintext string, err error)
}

type encrypter struct {
	key    []byte // key
	cipher string // encrypt method: AES-128-CBC or AES-256-CBC
}

type Payload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	Mac   string `json:"mac"`
}

type PayloadEncrypted struct {
	IV    []byte
	Value []byte
	Mac   []byte
}

func New(key string, cipher string) (*encrypter, error) {
	var err error

	if cipher == "" {
		cipher = "AES-256-CBC" // see php class EncryptionServiceProvider.
	}

	e := &encrypter{
		//key:    key,
		cipher: cipher,
	}

	if strings.HasPrefix(key, "base64:") {
		if e.key, err = base64.StdEncoding.DecodeString(key[7:]); err != nil {
			return nil, err
		}
	}

	if !e.supported() {
		return nil, errors.New("the only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.")
	}

	return e, nil
}

func (e *encrypter) Encrypt(value string, serialize bool) (string, error) {
	var err error
	if serialize {
		value, err = phpserialize.Encode(value)
		if err != nil {
			return "", errors.New("phpserialize.Encode failed: " + err.Error())
		}
	}

	var (
		p  Payload
		pe PayloadEncrypted
	)

	// IV
	pe.IV = randomBytes()
	p.IV = base64.StdEncoding.EncodeToString(pe.IV) // random_bytes(openssl_cipher_iv_length($this->cipher))

	// Value
	aesBlock, err := aes.NewCipher(e.key)
	if err != nil {
		return "", errors.New("aes.NewCipher failed:" + err.Error())
	}
	blockMode := cipher.NewCBCEncrypter(aesBlock, pe.IV)
	src := PKCS7Padding([]byte(value), aes.BlockSize)
	pe.Value = make([]byte, len(src))
	blockMode.CryptBlocks(pe.Value, src)
	p.Value = base64.StdEncoding.EncodeToString(pe.Value)

	// Mac
	p.Mac = e.hash(p.IV, p.Value)

	serializedEncrypted, err := json.Marshal(&p)
	if err != nil {
		return "", errors.New("json.Marshal failed: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(serializedEncrypted), nil
}

func (e *encrypter) Decrypt(playload string, serialize bool) (plaintext string, err error) {
	pe, err := e.getJsonPayload(playload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, pe.IV)

	plainbytes := make([]byte, len(pe.Value))
	mode.CryptBlocks(plainbytes, pe.Value)
	plainbytes = PKCS7UnPadding(plainbytes)

	// Value
	value := string(plainbytes)
	if serialize {
		v, err := phpserialize.Decode(value)
		if err != nil {
			return "", errors.New("phpserialize.Decode failed: " + err.Error())
		}
		value = v.(string)
	}

	return value, nil
}

func (e *encrypter) getJsonPayload(payload string) (*PayloadEncrypted, error) {
	var (
		p  Payload
		pe PayloadEncrypted
	)

	decodedBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("the payload is invalid.1")
	}

	err = json.Unmarshal(decodedBytes, &p)
	if err != nil {
		return nil, errors.New("the payload is invalid.2")
	}

	pe.Value, err = base64.StdEncoding.DecodeString(p.Value)
	if err != nil {
		return nil, errors.New("the payload is invalid.3")
	}

	pe.IV, err = base64.StdEncoding.DecodeString(p.IV)
	if err != nil {
		return nil, errors.New("the payload is invalid.4")
	}

	pe.Mac, err = base64.StdEncoding.DecodeString(p.Mac)
	if err != nil {
		return nil, errors.New("the payload is invalid.5")
	}

	if !e.validatePayload(&pe) {
		return nil, errors.New("the payload is invalid.6")
	}

	if !e.validateMac(&p) {
		return nil, errors.New("the payload is invalid.7")
	}

	return &pe, nil
}

func (e *encrypter) validatePayload(pe *PayloadEncrypted) bool {
	return len(pe.IV) == aes.BlockSize
}

func (e *encrypter) validateMac(p *Payload) bool {
	rnd := randomBytes()
	calculated := e.calculateMac(p, rnd)

	h := hmac.New(sha256.New, rnd)
	h.Write([]byte(p.Mac))

	return bytes.Equal(h.Sum(nil), calculated)
}

func (e *encrypter) hash(iv, value string) string {
	h := hmac.New(sha256.New, []byte(e.key))
	h.Write([]byte(iv + value))
	return hex.EncodeToString(h.Sum(nil)) // see https://github.com/php/php-src/blob/98fb565c7448cd455b8d24df5f6be8fcf9330fd7/ext/hash/hash.c#L566
	//return base64.StdEncoding.EncodeToString(h.Sum(nil)) // raw_output
}

func (e *encrypter) calculateMac(p *Payload, bytes []byte) []byte {
	content := e.hash(p.IV, p.Value)
	h := hmac.New(sha256.New, bytes)
	h.Write([]byte(content))

	return h.Sum(nil)
}

func (e *encrypter) supported() bool {
	length := len(e.key)

	return (e.cipher == "AES-128-CBC" && length == 16) ||
		(e.cipher == "AES-256-CBC" && length == 32)
}

func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func randomBytes() []byte {
	rnd := make([]byte, aes.BlockSize)
	rand.Read(rnd)
	return rnd
}
