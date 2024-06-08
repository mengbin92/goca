package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

// 生成RSA密钥对
func GenRSAKey(keySize int) (privateKey, publicKey string, err error) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, keySize)
	if err != nil {
		return "", "", errors.Wrap(err, "Generate RSA key failed")
	}
	privateKey = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	publicKey = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
	}))
	return
}
