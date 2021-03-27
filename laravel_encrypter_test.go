package golaravelencrypter

import (
	"testing"
)

func TestBasic(t *testing.T) {
	key := "base64:KGiEzh6m8sDmkikodA4yn1iWAG6sUgHfZoN6xlZVHC0="
	originaltext := `57616ee390aee4bcaf28ed7a815877d8`

	e, err := New(key, "")
	if err != nil {
		t.Fatalf("fail - %s", err)
	}

	chipertext, err := e.Encrypt(originaltext, false)
	if err != nil {
		t.Fatalf("fail - %s", err)
	}
	t.Log("chipertext: \n", chipertext)

	plaintext, err := e.Decrypt(chipertext, false)
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

	e, err := New(key, "")
	if err != nil {
		t.Fatalf("fail - %s", err)
	}

	plaintext, err := e.Decrypt(ciphertext, false)
	if err != nil {
		t.Errorf("fail - %s", err)
	}
	if plaintext == originaltext {
		t.Log("pass decrypt serialized php string variable")
	} else {
		t.Error("fail \nexpected:", originaltext, "\ngot     :", plaintext)
	}

	// ...
	plaintext1, err := e.Decrypt(ciphertext, true)
	if plaintext1 == originaltext1 {
		t.Log("pass decrypt unserialized php string variable")
	} else {
		t.Error("fail \nexpected:", originaltext1, "\ngot     :", plaintext1)
	}
}
