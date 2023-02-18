package src

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type IKey interface {
	SetPublicKey(path string)
	SetPrivateKey(path string)
	SetCommonKey(secret string)
	GetPublicKey() *rsa.PublicKey
	GetPrivateKey() *rsa.PrivateKey
	GetCommonKey() string
}

type Key struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CommonKey  string
}

func (k *Key) SetPublicKey(path string) {
	// Read the PEM file
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("pem private_key file reading error: %v", err))
	}
	// Decode the PEM data
	block, _ := pem.Decode(pemData)

	// Parse the RSA private key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("pem public_key parsing error: %v", err))
	}

	// Convert the public key to RSA format
	k.PublicKey = publicKey.(*rsa.PublicKey)
}
func (k *Key) SetPrivateKey(path string) {
	// Read the PEM file
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("pem private_key file reading error: %v", err))
	}
	// Decode the PEM data
	block, _ := pem.Decode(pemData)

	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("pem private_key parsing error: %v", err))
	}

	// Convert the private key to RSA format
	k.PrivateKey = privateKey
}
func (k *Key) SetCommonKey(secret string) {
	k.CommonKey = secret
}

func (k *Key) GetPublicKey() *rsa.PublicKey {
	return k.PublicKey
}
func (k *Key) GetPrivateKey() *rsa.PrivateKey {
	return k.PrivateKey
}
func (k *Key) GetCommonKey() string {
	return k.CommonKey
}
