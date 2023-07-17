package golaravelencrypter

import (
	"github.com/elliotchance/phpserialize"
	"testing"
)

func TestBasically(t *testing.T) {
	key := "base64:KGiEzh6m8sDmkikodA4yn1iWAG6sUgHfZoN6xlZVHC0="
	originaltext := `57616ee390aee4bcaf28ed7a815877d8`

	e, err := New(key, AES256CBC)
	if err != nil {
		t.Fatalf("fail - %s", err)
	}

	chipertext, err := e.Encrypt(originaltext)
	if err != nil {
		t.Fatalf("fail - %s", err)
	}
	t.Log("chipertext: \n", chipertext)

	plaintext, err := e.Decrypt(chipertext)
	if err != nil {
		t.Fatalf("fail - %s", err)
	}

	if originaltext == plaintext {
		t.Log("pass")
	} else {
		t.Error("fail \nexpected:", originaltext, "\ngot     :", plaintext)
	}
}

func TestWithSerialization(t *testing.T) {
	key := "base64:KGiEzh6m8sDmkikodA4yn1iWAG6sUgHfZoN6xlZVHC0="
	originaltext := `s:32:"57616ee390aee4bcaf28ed7a815877d7";`
	originaltext1 := `57616ee390aee4bcaf28ed7a815877d7`
	ciphertext := "eyJpdiI6ImJMUXhPUjA5UHdmVGRBaFN1eWRcL0lRPT0iLCJ2YWx1ZSI6IjVpZDYzd0ZOUGY2ZDArcFgzNXo4eEVydjBzWEppMTl2OVltQVcwR3Fjd2VQT1FJRENVdGsyU3laM1d1Y3JySVgiLCJtYWMiOiJiOWU2MTU3Y2FjODUwM2MzMDRmZGFiNDRiN2FkYjA5MTM1YjQ2MGUzYmRmZTgzNDExOGVlZTc2ZjdhYjJmOWM0In0="

	e, err := New(key, AES256CBC)
	if err != nil {
		t.Fatalf("fail - %s", err)
	}

	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("fail - %s", err)
	}
	if plaintext == originaltext {
		t.Log("pass decrypt unserialized php string variable")
	} else {
		t.Error("fail \nexpected:", originaltext, "\ngot     :", plaintext)
	}

	// ...
	serializedPHPStr, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("fail - %s", err)
	}
	plaintext1, err := phpserialize.UnmarshalString([]byte(serializedPHPStr))
	if err != nil {
		t.Errorf("fail - %s", err)
	}
	if plaintext1 == originaltext1 {
		t.Log("pass decrypt serialized php string variable")
	} else {
		t.Error("fail \nexpected:", originaltext1, "\ngot     :", plaintext1)
	}
}

func TestAES128Decryption(t *testing.T) {
	key := "base64:HfEy8zJBQn7EzR2w+B+j5w=="
	originaltext := `s:6:"123456";`
	ciphertext := "eyJpdiI6ImMwbkg5YXBLUGhZRW1jYWlZaklPY2c9PSIsInZhbHVlIjoiUDdOaEZOQ3h3QWdQSFM3M3pUSEIyQT09IiwibWFjIjoiMDI3Zjk0NWY2NTg1MzBiMGVjMjBkNzVlNzBhM2MxOWVlYmVlZTQxNzA1M2FkNmI2OWRhOWQ3Y2JmNjNiODNhMiJ9"

	e, err := New(key, AES128CBC)
	if err != nil {
		t.Fatalf("fail - %s", err)
	}

	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("fail - %s", err)
	}
	if plaintext == originaltext {
		t.Log("pass decrypt serialized php string variable")
	} else {
		t.Error("fail \nexpected:", originaltext, "\ngot     :", plaintext)
	}
}
