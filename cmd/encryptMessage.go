package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"log"

	"jmessage_2024/config"
	"jmessage_2024/utils"

	"golang.org/x/crypto/chacha20"
)

// Assuming a function signature like this to include the private key for signing:
func EncryptMessage(message []byte, senderUsername string, recipientPubKey *config.PubKeyStruct) (messageEncrypted []byte, err error) {
	/**
	encPK, sP: recipient's public key
	c: random scalar value, sender's encSK
	cP, epk: ephemeral public key, encPK
	s: recipients encSK
	sP: recipients encPK
	ssk, csP: shared secret (key)
	K: secret key = sha256(ssk)
	c1: encoded emphemeral public key
	*/

	/**
	Compute c1 and K
	*/
	privKey := config.Global.GlobalPrivKey

	senderEncSK, err := utils.DecodeECDHPrivateKey(privKey.EncSK)
	if err != nil {
		log.Fatalf("Error decoding the ecdsa private key: %v", err)
	}

	// Decode recipient's public key (encPK)
	recEncPK, err := utils.DecodePublicKey(recipientPubKey.EncPK)
	if err != nil {
		log.Fatalf("Error decoding recipient key: %v", err)
		return nil, err
	}

	// generate a random scalar c

	ssk, err := senderEncSK.ECDH(recEncPK)
	if err != nil {
		log.Fatalf("Error doing ecdh: %v", err)
		return nil, err
	}

	// The sender computes K = SHA256(ssk) where * represents scalar point multiplication. This key K will be used in the next section.
	K := sha256.Sum256(ssk)

	senderPubKey := config.Global.GlobalPubKey

	senderEncPK, err := utils.DecodePublicKey(senderPubKey.EncPK)
	if err != nil {
		log.Fatalf("Error doing ecdh: %v", err)
		return nil, err
	}

	senderEncPKBytes, err := x509.MarshalPKIXPublicKey(senderEncPK)
	if err != nil {
		log.Fatalf("Error doing ecdh: %v", err)
		return nil, err
	}
	c1 := base64.StdEncoding.EncodeToString(senderEncPKBytes)

	/**
	Compute c2
	*/

	// Step 1: Construct M'
	separator := []byte{0x3A} // byte representation of ":"
	mPrime := append([]byte(senderUsername), separator...)
	mPrime = append(mPrime, message...)

	// Step 2: Compute CHECK = CRC32(M')
	check := crc32.ChecksumIEEE(mPrime)
	checkBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(checkBytes, check)

	// Step 3: Construct M'' = M' || CHECK
	mDoublePrime := append(mPrime, checkBytes...)

	// Step 4: Encrypt M'' using ChaCha20
	// The nonce for ChaCha20 is 12 bytes, here it's set to zeros, which is suitable for unique keys per encryption
	nonce := make([]byte, 12) // Initialize a nonce with zeros
	cipher, err := chacha20.NewUnauthenticatedCipher(K[:], nonce)
	if err != nil {
		log.Fatalf("Error creating ChaCha20 cipher: %v", err)
	}

	encrypted := make([]byte, len(mDoublePrime))
	cipher.XORKeyStream(encrypted, mDoublePrime)

	// Step 5: BASE64 encode the encrypted message
	c2 := base64.StdEncoding.EncodeToString(encrypted)

	/**
	Compute Sig
	*/
	toSign := c1 + c2 // Concatenating c1 and c2

	// Sign the string toSign using ECDSA with P-256
	sig := ECDSASign([]byte(toSign), privKey)

	// Encode the resulting signature using BASE64
	Sig := base64.StdEncoding.EncodeToString(sig)

	// Now you have c1, c2, and Sig, you can return them or do further processing
	// For demonstration, let's just log them and return an example byte slice
	// log.Printf("c1: %s\nc2: %s\nSig: %s", c1, c2, Sig)

	payload := config.CiphertextStruct{
		C1:  c1,
		C2:  c2,
		Sig: Sig,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("Error signing the message: %v", err)
	}

	return payloadBytes, err

	// Usage of the function would then require the message, sender username, recipient public key struct, and sender private key struct.
}
