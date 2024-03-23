package cmd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"jmessage_2024/config"
	"jmessage_2024/utils"
	"log"
	"math/big"
	"os"

	"golang.org/x/crypto/chacha20"
)

type Signature struct {
	R *big.Int
	S *big.Int
}

func DecryptMessage(payload string, senderUsername string, senderPubKey *config.PubKeyStruct, recipientPrivKey *config.PrivKeyStruct) (message []byte, err error) {
	// TODO: IMPLEMENT

	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Fatalf("Error base64 decoding payload: %v", err)
		return nil, err
	}

	var ciphertext config.CiphertextStruct

	err = json.Unmarshal([]byte(payloadBytes), &ciphertext)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(ciphertext.Sig)

	toVerify := ciphertext.C1 + ciphertext.C2

	ecdsaToVerify := sha256.Sum256([]byte(toVerify))

	senderSigPK, err := decodePublicKey(senderPubKey.SigPK)
	if err != nil {
		log.Fatalf("Failed to decode sender SigPK JSON: %v", err)
	}

	// Verify the signature
	if verifySignature(senderSigPK, ecdsaToVerify[:], sigBytes) {
		fmt.Println("Signature verified!")
	} else {
		fmt.Println("Signature verification failed.")
	}

	K, err := decodeC1ObtainK(ciphertext.C1)
	if err != nil {
		log.Fatalf("Failed to decode C2 and obtain K: %v", err)
	}

	sender, message, err := decryptC2(ciphertext.C2, K)
	if err != nil {
		log.Fatalf("Failed to decrypt C2 %v", err)
	}
	if string(sender) != senderUsername {
		log.Fatalf("Failed to decrypt C2 %v", err)
		os.Exit(1)
	}

	return message, err
}

func verifySignature(pubKey *ecdsa.PublicKey, toVerify []byte, signature []byte) bool {
	// Hash the data if the signature was created over a hash

	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
	sig := Signature{
		R: r,
		S: s}

	verified := ecdsa.Verify(pubKey, toVerify, sig.R, sig.S)
	return verified
}

func decodePublicKey(base64PubKey string) (pubKey *ecdsa.PublicKey, err error) {
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
	return ecdsaPubKey, err
}

func decodeC1ObtainK(base64C1 string) (K [32]byte, err error) {
	c1Byte, err := base64.StdEncoding.DecodeString(base64C1)
	if err != nil {
		log.Fatalf("Error decoding c1: %v", err)
	}

	senderEncPK, err := x509.ParsePKIXPublicKey(c1Byte)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}

	ecdsaPubKey, ok := senderEncPK.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Not an ECDSA public key")
	}
	ecdhPK, err := ecdsaPubKey.ECDH()
	if err != nil {
		log.Fatalf("Not an ECDH public key: %v", err)
		return
	}

	// fileContent, err := os.ReadFile("cred/globalKeys.json")
	// if err != nil {
	// 	log.Fatalf("Error read file error: %v", err)
	// 	return
	// }

	// var privKey config.PrivKeyStruct
	// err = json.Unmarshal(fileContent, &privKey)
	// if err != nil {
	// 	log.Fatalf("Error unmarshal privatekey error: %v", err)
	// 	return
	// }

	encSK, err := utils.DecodeECDHPrivateKey(config.Global.GlobalPrivKey.EncSK)
	if err != nil {
		log.Fatalf("Error decoding the ecdsa private key: %v", err)
	}

	ssk, err := encSK.ECDH(ecdhPK)
	if err != nil {
		log.Fatalf("Error decoding the ecdsa private key: %v", err)
	}
	K = sha256.Sum256(ssk)

	println("K", base64.StdEncoding.EncodeToString(K[:]))
	return K, err
}

func decryptC2(c2 string, K [32]byte) (senderUsername []byte, message []byte, err error) {
	// Step 1: BASE64 Decode C2
	encrypted, err := base64.StdEncoding.DecodeString(string(c2))
	if err != nil {
		log.Fatalf("Error decoding C2 from base64: %v", err)
		return nil, nil, err
	}

	// Step 2: Decrypt using ChaCha20
	nonce := make([]byte, 12) // Same nonce as used during encryption
	cipher, err := chacha20.NewUnauthenticatedCipher(K[:], nonce)
	if err != nil {
		log.Fatalf("Error creating ChaCha20 cipher for decryption: %v", err)
		return nil, nil, err
	}

	decrypted := make([]byte, len(encrypted))
	cipher.XORKeyStream(decrypted, encrypted)

	// Step 3: Verify and Remove CHECK
	if len(decrypted) < 4 {
		log.Fatalf("Decrypted message is too short to contain a valid CHECK value")
		return nil, nil, err
	}
	checkBytes := decrypted[len(decrypted)-4:]
	decrypted = decrypted[:len(decrypted)-4] // Remove CHECK from the message
	check := binary.LittleEndian.Uint32(checkBytes)
	calculatedCheck := crc32.ChecksumIEEE(decrypted)

	if check != calculatedCheck {
		log.Fatalf("CRC32 CHECK mismatch, message integrity could not be verified")
		return nil, nil, err
	}

	// Step 4: Extract the Original Message and Sender Username
	separatorIndex := -1
	for i, b := range decrypted {
		if b == 0x3A { // ':' separator
			separatorIndex = i
			break
		}
	}

	if separatorIndex == -1 {
		log.Fatalf("Separator not found in decrypted message")
		return nil, nil, err
	}

	senderUsername = decrypted[:separatorIndex]
	message = decrypted[separatorIndex+1:]

	return senderUsername, message, err
}
