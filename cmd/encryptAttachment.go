package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/chacha20"
)

func EncryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, string, error) {
	// TODO: IMPLEMENT
	// Step 1: Generate a random 256-bit key for ChaCha20.
	key := make([]byte, 32) // 256 bits for ChaCha20
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Error generating random ChaCha20 key: %v", err)
		return "", "", err
	}

	// The zero IV for ChaCha20.
	iv := make([]byte, chacha20.NonceSize)

	// Step 2: Create a new ChaCha20 cipher instance.
	cipher, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		log.Fatalf("Error creating ChaCha20 cipher: %v", err)
	}

	// Step 3: Open the plaintext file.
	plaintext, err := os.Open(plaintextFilePath)
	if err != nil {
		log.Fatalf("Error opening plaintext file, %v", err)
		return "", "", err
	}
	defer plaintext.Close()

	// Read the entire file into memory - consider streaming for large files!
	plaintextBytes, err := io.ReadAll(plaintext)
	if err != nil {
		log.Fatalf("Error opening plaintext file, %v", err)
		return "", "", err
	}

	// Encrypt the file content.
	ciphertext := make([]byte, len(plaintextBytes))
	cipher.XORKeyStream(ciphertext, plaintextBytes)

	// Step 4: Compute SHA256 hash of the encrypted file.
	hash := sha256.Sum256(ciphertext)

	// Step 5: Write the ciphertext to a new file.
	if err := os.WriteFile(ciphertextFilePath, ciphertext, 0644); err != nil {
		return "", "", err
	}

	// Return the hex-encoded key and file hash.
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(hash[:]), nil
}
