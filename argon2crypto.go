package argon2crypto

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func GetHashedPassword(password string, p Params) (encodedHash string, salt []byte, err error) {
	salt, err = GenerateRandomBytes(p.SaltLength)
	if err != nil { return "", []byte(""), err }
	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash = string(p.Memory) + b64salt + string(p.Iterations) + b64hash + string(p.Parallelism)
	return encodedHash, salt,nil
}

func GenerateRandomBytes(n uint32) ([]byte, error) {
	rawBytes := make([]byte, n)
	_, err := rand.Read(rawBytes)
	if err != nil { return  nil, err }
	return rawBytes, nil
}

func Check(dbPassword string, dbSalt []byte, received string, p Params) bool {
	hash := argon2.IDKey([]byte(received), dbSalt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64salt := base64.RawStdEncoding.EncodeToString(dbSalt)
	b64hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash := string(p.Memory) + b64salt + string(p.Iterations) + b64hash + string(p.Parallelism)
	if encodedHash == dbPassword { return true }
	return false
}