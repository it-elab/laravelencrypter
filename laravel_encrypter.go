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
	//"github.com/wulijun/go-php-serialize/phpserialize"
	"github.com/elliotchance/phpserialize"
	"strings"
)

const AES128CBC = "AES-128-CBC"
const AES256CBC = "AES-256-CBC"

type Encrypter interface {
	Encrypt(value string, serialize bool) (ciphertext string, err error)
	Decrypt(playload string, serialize bool) (plaintext string, err error)
}

type encrypter struct {
	key    []byte // key
	cipher string // encrypt method: AES-128-CBC or AES-256-CBC
}

type payloadString struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	Mac   string `json:"mac"`
}

type payloadBytes struct {
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
		cipher: cipher, // 256 or 128 doesn't make much sense in go crypto package?
	}

	if strings.HasPrefix(key, "base64:") {
		key = key[7:]
	}
	if e.key, err = base64.StdEncoding.DecodeString(key); err != nil {
		return nil, err
	}

	if !e.supported() {
		return nil, errors.New("the only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.")
	}

	return e, nil
}

func (e *encrypter) Encrypt(value string, serialize bool) (ciphertext string, err error) {
	var (
		plainbytes []byte
		ps         payloadString
		pb         payloadBytes
	)

	if serialize {
		plainbytes = phpserialize.MarshalString(value)
	} else {
		plainbytes = []byte(value)
	}

	// IV
	pb.IV = randomBytes(aes.BlockSize)
	ps.IV = base64.StdEncoding.EncodeToString(pb.IV) // random_bytes(openssl_cipher_iv_length($this->cipher))

	// Value
	aesBlock, err := aes.NewCipher(e.key)
	if err != nil {
		return "", errors.New("aes.NewCipher failed:" + err.Error())
	}
	blockMode := cipher.NewCBCEncrypter(aesBlock, pb.IV)
	src := pkcs7Padding(plainbytes, aes.BlockSize)
	pb.Value = make([]byte, len(src))
	blockMode.CryptBlocks(pb.Value, src)
	ps.Value = base64.StdEncoding.EncodeToString(pb.Value)

	// Mac
	ps.Mac = e.hash(ps.IV, ps.Value)

	serializedEncrypted, err := json.Marshal(&ps)
	if err != nil {
		return "", errors.New("json.Marshal failed: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(serializedEncrypted), nil
}

func (e *encrypter) Decrypt(playload string, serialize bool) (plaintext string, err error) {
	pb, err := e.getJsonPayload(playload)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return
	}
	mode := cipher.NewCBCDecrypter(block, pb.IV)

	plainbytes := make([]byte, len(pb.Value))
	mode.CryptBlocks(plainbytes, pb.Value)
	plainbytes = pkcs7Unpadding(plainbytes)

	// Value
	if serialize {
		plaintext, err = phpserialize.UnmarshalString(plainbytes)
		if err != nil {
			return "", errors.New("phpserialize.Decode failed: " + err.Error())
		}
		return
	}

	return string(plainbytes), nil
}

func (e *encrypter) getJsonPayload(payload string) (*payloadBytes, error) {
	var (
		ps payloadString
		pb payloadBytes
	)

	decodedBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("the payload is invalid.1")
	}

	err = json.Unmarshal(decodedBytes, &ps)
	if err != nil {
		return nil, errors.New("the payload is invalid.2")
	}

	pb.Value, err = base64.StdEncoding.DecodeString(ps.Value)
	if err != nil {
		return nil, errors.New("the payload is invalid.3")
	}

	pb.IV, err = base64.StdEncoding.DecodeString(ps.IV)
	if err != nil {
		return nil, errors.New("the payload is invalid.4")
	}

	pb.Mac, err = base64.StdEncoding.DecodeString(ps.Mac)
	if err != nil {
		return nil, errors.New("the payload is invalid.5")
	}

	if !e.validatePayload(&pb) {
		return nil, errors.New("the payload is invalid.6")
	}

	if !e.validateMac(&ps) {
		return nil, errors.New("the payload is invalid.7")
	}

	return &pb, nil
}

func (e *encrypter) validatePayload(pb *payloadBytes) bool {
	return len(pb.IV) == aes.BlockSize
}

func (e *encrypter) validateMac(ps *payloadString) bool {
	rnd := randomBytes(aes.BlockSize)
	calculated := e.calculateMac(ps, rnd)

	h := hmac.New(sha256.New, rnd)
	h.Write([]byte(ps.Mac))

	return bytes.Equal(h.Sum(nil), calculated)
}

func (e *encrypter) hash(iv, value string) string {
	h := hmac.New(sha256.New, []byte(e.key))
	h.Write([]byte(iv + value))
	return hex.EncodeToString(h.Sum(nil)) // lowercase hexits, see https://github.com/php/php-src/blob/98fb565c7448cd455b8d24df5f6be8fcf9330fd7/ext/hash/hash.c#L566
	//return h.Sum(nil) // raw_output
}

func (e *encrypter) calculateMac(ps *payloadString, bytes []byte) []byte {
	content := e.hash(ps.IV, ps.Value)
	h := hmac.New(sha256.New, bytes)
	h.Write([]byte(content))

	return h.Sum(nil)
}

func (e *encrypter) supported() bool {
	length := len(e.key)

	return (e.cipher == "AES-128-CBC" && length == 16) ||
		(e.cipher == "AES-256-CBC" && length == 32)
}

func pkcs7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7Unpadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func randomBytes(len int) []byte {
	rnd := make([]byte, len)
	rand.Read(rnd)
	return rnd
}
