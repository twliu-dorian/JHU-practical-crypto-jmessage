package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"regexp"

	"jmessage_2024/config"

	"golang.org/x/crypto/chacha20"
)

func DecryptFileContent(messageArray []config.MessageStruct) (err error) {
	if len(messageArray) == 0 {
		return
	}

	plaintextFilePath := "JMESSAGE_DOWNLOADS/decryptedPlain"

	// pattern := `>>>MSGURL=(https:\/\/localhost:8080\/downloadFile\/matthew\/([^?]+))\?KEY=([^?]+)\?H=([^=]+)=`

	pattern := `>>>MSGURL=([^?]+)\?KEY=([^?]+)\?H=([^=]+=)`
	re := regexp.MustCompile(pattern)

	// Use regex to find submatches in the message

	for i := 0; i < len(messageArray); i++ {
		message := messageArray[i].Decrypted
		matches := re.FindStringSubmatch(message)
		var sourceHash, key, ciphertextHash, url string
		var ciphertextData []byte
		if matches != nil && len(matches) >= 3 {
			// matches[0] is the full match, matches[1] is the URL, matches[2] is the KEY, matches[3] is the H

			url = matches[1]
			key = matches[2]
			sourceHash = matches[3]

			fmt.Println("URL:", url)
			fmt.Println("KEY:", key)
			fmt.Println("H:", sourceHash)
			var originHashBytes [32]byte

			if messageArray[i].LocalPath != "" {
				ciphertextData, err = os.ReadFile(messageArray[i].LocalPath)
				if err != nil {
					log.Fatalf("Failed to read file: %v", err)
				}
				fmt.Println("cipher text data", string(ciphertextData))

				originHashBytes = sha256.Sum256(ciphertextData)

				ciphertextHash = base64.StdEncoding.EncodeToString(originHashBytes[:])
			}
			fmt.Println("ciphertextHash", ciphertextHash)
			fmt.Println("sourceHash", sourceHash)

			if sourceHash != ciphertextHash {
				log.Fatalf("source hash and cipher text hash doesn't match")
			}
			keyBytes, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				log.Fatalf("fail to decode base 64 chacha20 key: %v", err)
			}

			datPattern := regexp.MustCompile(`([^/]+\.dat)`)
			datFilename := datPattern.FindStringSubmatch(url)
			plaintextFilePath := plaintextFilePath + datFilename[0]
			plaintextData, err := decryptFile(keyBytes, ciphertextData)
			if err != nil {
				log.Fatalf("Error decoding file: %v", err)
			}
			fmt.Println("plain text data", string(plaintextData))
			if err := os.WriteFile(plaintextFilePath, plaintextData, 0644); err != nil {
				log.Fatalf("Error writing plaintext file: %v", err)
				return err
			}
		}

	}
	return err
}

func decryptFile(key []byte, ciphertext []byte) (plaintext []byte, err error) {

	// The zero IV for ChaCha20, assuming the same was used for encryption.
	iv := make([]byte, chacha20.NonceSize)

	// Create a new ChaCha20 cipher instance with the same key and IV.
	cipher, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		log.Fatalf("Error creating ChaCha20 cipher: %v", err)
		return nil, err
	}

	// Decrypt the file content.
	plaintext = make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)

	return plaintext, err
}
