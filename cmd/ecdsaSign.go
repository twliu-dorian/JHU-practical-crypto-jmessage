package cmd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"jmessage_2024/config"
	"jmessage_2024/utils"
	"log"
)

func ECDSASign(message []byte, privKey config.PrivKeyStruct) []byte {
	// TODO: IMPLEMENT

	senderSigSK, err := utils.DecodePrivateSigningKey(privKey.SigSK)
	if err != nil {
		log.Fatalf("Error decoding the ecdsa private key: %v", err)
	}

	ecdasToSign := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, senderSigSK, ecdasToSign[:])
	if err != nil {
		log.Fatalf("Error signing the message: %v", err)
	}

	sig := r.Bytes()
	sig = append(sig, s.Bytes()...)

	return sig
}
