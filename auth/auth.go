package auth

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"jmessage_2024/api"
	"jmessage_2024/config"
)

// Register config.Global.Username with the server
func RegisterUserWithServer(username string, password string) error {
	geturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := api.DoGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// // Upload a new public key to the server
func RegisterPublicKeyWithServer(username string, pubKeyEncoded config.PubKeyStruct) error {
	posturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/uploadKey/" +
		username + "/" + config.ApiKey.APIkey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := api.DoPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Log in to server
func ServerLogin(username string, password string) (string, error) {
	geturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := api.DoGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("Bad result code")
	}

	// Parse JSON into an APIKey struct
	var result config.APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Generate a fresh public key struct, containing encryption and signing keys
func GeneratePublicKey() (config.PubKeyStruct, config.PrivKeyStruct, error) {
	var pubKey config.PubKeyStruct
	var privKey config.PrivKeyStruct

	// Generate a random private key for encryption (a)
	encPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return pubKey, privKey, err
	}
	encPublicKey := encPrivateKey.PublicKey()

	// Encode the private key using PKCS#8
	encSKBytes, err := x509.MarshalPKCS8PrivateKey(encPrivateKey)
	if err != nil {
		return pubKey, privKey, err
	}
	privKey.EncSK = base64.StdEncoding.EncodeToString(encSKBytes)

	// Compute pk (public key) and encode it
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(encPublicKey)
	if err != nil {
		return pubKey, privKey, err
	}
	pubKey.EncPK = base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Repeat the process for the signing key (b)
	sigPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return pubKey, privKey, err
	}
	sigPublicKey := sigPrivateKey.PublicKey()

	// Encode the private key using PKCS#8
	sigSKBytes, err := x509.MarshalPKCS8PrivateKey(sigPrivateKey)
	if err != nil {
		return pubKey, privKey, err
	}
	privKey.SigSK = base64.StdEncoding.EncodeToString(sigSKBytes)

	// Compute vk (public key) and encode it
	sigPubKeyBytes, err := x509.MarshalPKIXPublicKey(sigPublicKey)
	if err != nil {
		return pubKey, privKey, err
	}
	pubKey.SigPK = base64.StdEncoding.EncodeToString(sigPubKeyBytes)

	// println("Encryption Public Key:", pubKey.EncPK)
	// println("Signing Public Key:", pubKey.SigPK)
	// println("Encryption Private Key:", privKey.EncSK)
	// println("Signing Private Key:", privKey.SigSK)

	return pubKey, privKey, nil
}
