package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"strings"
)

func ComputeFingerPrint(username string) (fingerprint string, err error) {
	userPubKey, err := GetPublicKeyFromServer(username)
	if err != nil {
		log.Fatalf("Error get public key from server: %v", err)
	}
	encPKBytes, err := base64.StdEncoding.DecodeString(userPubKey.EncPK)
	if err != nil {
		log.Fatalf("Error decoding enc pk: %v", err)
	}
	sigPKBytes, err := base64.StdEncoding.DecodeString(userPubKey.EncPK)
	if err != nil {
		log.Fatalf("Error decoding enc pk: %v", err)
	}
	data := append(encPKBytes, sigPKBytes...)

	// Compute SHA256 hash of the concatenated keys
	hash := sha256.Sum256(data)

	// Truncate the hash to the first 10 bytes
	truncated := Truncate(hash[:], 10)

	// Encode the truncated hash in hexadecimal notation
	fingerprint = hex.EncodeToString(truncated)

	return formatFingerprint(fingerprint), err
}

func formatFingerprint(fingerprint string) string {
	formatted := ""
	for i, r := range fingerprint {
		if i%2 == 0 && i != 0 {
			formatted += " "
		}
		formatted += string(r)
	}
	return strings.ToUpper(formatted)
}

func Truncate(data []byte, n int) []byte {
	if n > len(data) {
		return data
	}
	return data[:n]
}
