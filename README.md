Go laravel encrypter
===
Generally use to encrypt/decrypt laravel session/cookie in golang program.
For replace laravel web page/api with golang gradually.

# Usage
```go
key := "base64:KGiEzh6m8sDmkikodA4yn1iWAG6sUgHfZoN6xlZVHC0=" // see laravel .env file
originaltext := `57616ee390aee4bcaf28ed7a815877d8`

encrypter, err := New(key, "")
// ...
chipertext, err := encrypter.Encrypt(originaltext, false)// app('encrypter')->encrypt()

// ...
plaintext, err := encrypter.Decrypt(chipertext, false)
```


# Reference
- https://github.com/laravel/framework/blob/v5.8.37/src/Illuminate/Encryption/Encrypter.php
- https://github.com/chekun/golaravelsession
- https://github.com/forgoer/openssl
- https://github.com/php/php-src/blob/98fb565c7448cd455b8d24df5f6be8fcf9330fd7/ext/hash/hash.c#L587
