package utils

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"log"
)

func DecodePublicKey(base64PubKey string) (pubKey *ecdh.PublicKey, err error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		log.Fatalf("Error base64 decoding recipient's key: %v", err)
		return nil, err
	}
	pubKeyAny, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		log.Fatalf("Error parsing pkcs8 public key: %v", err)
		return nil, err
	}

	ecdsaPubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("not a ecdsa puclic key: %v", err)
		return nil, err
	}

	pubKey, err = ecdsaPubKey.ECDH()
	if err != nil {
		log.Fatalf("Error converting ecdsa pubkey to ecdh: %v", err)
		return nil, err
	}

	return pubKey, err
}

func DecodePrivateSigningKey(base64PrivKey string) (privKey *ecdsa.PrivateKey, err error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(base64PrivKey)
	if err != nil {
		log.Fatalf("Error base64 decoding signing's key: %v", err)
		return nil, err
	}

	privKeyAny, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		log.Fatalf("Error parsing pkcs8 private key: %v", err)
		return nil, err
	}

	privKey, ok := privKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("not a ecdsa private key: %v", err)
		return nil, err
	}

	return privKey, nil
}

func DecodeECDHPrivateKey(base64PrivKey string) (privKey *ecdh.PrivateKey, err error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(base64PrivKey)
	if err != nil {
		log.Fatalf("Error base64 decoding signing's key: %v", err)
		return nil, err
	}

	privKeyAny, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		log.Fatalf("Error parsing pkcs8 private key: %v", err)
		return nil, err
	}

	ecdsaPrivKey, ok := privKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("not a ecdsa private key: %v", err)
		return nil, err
	}

	privKey, err = ecdsaPrivKey.ECDH()
	if err != nil {
		log.Fatalf("Error converting ecdsa pubkey to ecdh: %v", err)
		return nil, err
	}

	return privKey, nil
}
