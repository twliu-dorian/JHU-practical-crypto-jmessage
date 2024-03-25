package cmd

import (
	"crypto/ecdsa"
	"crypto/rand"
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

// func decodePublicKey(base64PubKey string) (pubKey *ecdh.PublicKey, err error) {
// 	pubKeyBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
// 	if err != nil {
// 		log.Fatalf("Error base64 decoding recipient's key: %v", err)
// 		return nil, err
// 	}
// 	pubKeyAny, err := x509.ParsePKIXPublicKey(pubKeyBytes)
// 	if err != nil {
// 		log.Fatalf("Error parsing pkcs8 public key: %v", err)
// 		return nil, err
// 	}

// 	// switch ecdhPubKeyAny := ecdhPubKeyAny.(type) {
// 	// case *rsa.PublicKey:
// 	// 	fmt.Println("pub is of type RSA:", ecdhPubKeyAny)
// 	// case *ecdsa.PublicKey:
// 	// 	fmt.Println("pub is of type ECDSA:", ecdhPubKeyAny)
// 	// case ed25519.PublicKey:
// 	// 	fmt.Println("pub is of type Ed25519:", ecdhPubKeyAny)
// 	// default:
// 	// 	panic("unknown type of public key")
// 	// }

// 	ecdsaPubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
// 	if !ok {
// 		log.Fatalf("not a ecdsa puclic key: %v", err)
// 		return nil, err
// 	}

// 	pubKey, err = ecdsaPubKey.ECDH()
// 	if err != nil {
// 		log.Fatalf("Error converting ecdsa pubkey to ecdh: %v", err)
// 		return nil, err
// 	}

// 	// publicKey, err = ecdh.P256().NewPublicKey(ecdhPubKey.Bytes())
// 	// if err != nil {
// 	// 	log.Fatalf("Error recipient's key is not P256: %v", err)
// 	// 	return nil, err
// 	// }
// 	return pubKey, err
// }

// Function to decode the private signing key from BASE64
// func decodePrivateKey(base64PrivKey string) (privKey *ecdsa.PrivateKey, err error) {
// 	privKeyBytes, err := base64.StdEncoding.DecodeString(base64PrivKey)
// 	if err != nil {
// 		log.Fatalf("Error base64 decoding signing's key: %v", err)
// 		return nil, err
// 	}
// 	block, _ := pem.Decode(privKeyBytes)
// 	if block == nil || block.Type != "PRIVATE KEY" {
// 		log.Fatal("Failed to decode PEM block containing private key")
// 	}

// 	// Now, block.Bytes contains the original byte slice of the private key (sigSKBytes)
// 	sigSKBytes := block.Bytes

// 	privKeyAny, err := x509.ParsePKCS8PrivateKey(sigSKBytes)
// 	if err != nil {
// 		log.Fatalf("Error parsing pkcs8 private key: %v", err)
// 		return nil, err
// 	}

// 	privKey, ok := privKeyAny.(*ecdsa.PrivateKey)
// 	if !ok {
// 		log.Fatalf("not a ecdsa private key: %v", err)
// 		return nil, err
// 	}

// 	// privKey, err = ecdsaPrivKey.ECDH()
// 	// if err != nil {
// 	// 	log.Fatalf("Error converting ecdsa pubkey to ecdh: %v", err)
// 	// 	return nil, err
// 	// }

// 	return privKey, nil
// }

// Assuming a function signature like this to include the private key for signing:
func EncryptMessage(message []byte, senderUsername string, recipientPubKey *config.PubKeyStruct) (messageEncrypted []byte, err error) {
	/**
		encPK, sP: recipient's public key
		c: random scalar value, sender's encSK
		cP, epk: ephemeral public key, encPK
		csP: shared secret
		s: recipients encSK
		sP: recipients encPK
		ssk: shared secret key
		K: secret key = sha256(ssk)
		c1: encoded emphemeral public key
	/
	/**
		Compute c1 and K
	*/
	privKey := config.Global.GlobalPrivKey

	senderSigSK, err := utils.DecodePrivateKey(privKey.SigSK)
	if err != nil {
		log.Fatalf("Error decoding the ecdsa private key: %v", err)
	}

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
	println("K", base64.StdEncoding.EncodeToString(K[:]))

	senderPubKey := config.Global.GlobalPubKey
	println("sender enc PK", senderPubKey.EncPK)

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
	println("toSign", toSign)

	// Sign the string toSign using ECDSA with P-256
	ecdasToSign := sha256.Sum256([]byte(toSign))
	r, s, err := ecdsa.Sign(rand.Reader, senderSigSK, ecdasToSign[:])
	if err != nil {
		log.Fatalf("Error signing the message: %v", err)
	}

	println("r", r.String())
	println("s", s.String())

	sig := r.Bytes()
	sig = append(sig, s.Bytes()...) // Concatenate R and S components of the signature

	// Encode the resulting signature using BASE64
	Sig := base64.StdEncoding.EncodeToString(sig)

	// Now you have c1, c2, and Sig, you can return them or do further processing
	// For demonstration, let's just log them and return an example byte slice
	log.Printf("c1: %s\nc2: %s\nSig: %s", c1, c2, Sig)

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
