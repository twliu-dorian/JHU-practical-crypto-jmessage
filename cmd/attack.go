package cmd

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"jmessage_2024/auth"
	"jmessage_2024/config"
	"log"
	"os"
	"time"
)

func Attack(victimName string) (plaintext string, err error) {
	interceptedFilePath := "cipher.json"

	message, err := readInterceptedMessage(interceptedFilePath)
	if err != nil {
		log.Fatalf("Error reading intercepted message: %v", err)
		return
	}
	// check victim name == message.To
	if message.To != victimName {
		fmt.Printf("Wrong victim to attack %s", victimName)
	}

	// start attack

	username := message.From
	config.Global.Username = username
	fmt.Printf("username: %s\n", username)

	payloadBytes, err := base64.StdEncoding.DecodeString(message.Payload)
	if err != nil {
		log.Fatalf("Error base64 decoding payload: %v", err)
		return
	}

	var ciphertext config.CiphertextStruct

	err = json.Unmarshal([]byte(payloadBytes), &ciphertext)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	c2Bytes, _ := base64.StdEncoding.DecodeString(ciphertext.C2)

	// len(c2) - len(username) - len(CRC32) - len(':') - len('\n')
	lenCiphertext := len(c2Bytes) - len(username) - 4 - 1 - 1

	fmt.Printf("length of message to decrypt: %d\n", lenCiphertext)
	crcC2Bytes := make([]byte, len(c2Bytes))
	var decryptedMessage = ""
	for i := 0; i < lenCiphertext; i++ {
		var newAPIkey string
		var globalPubKey config.PubKeyStruct
		var globalPrivKey config.PrivKeyStruct
		var decryptedByte string
		config.Global.Username = config.Global.Username + "a"
		config.Global.Password = "1234"

		err = auth.RegisterUserWithServer(config.Global.Username, config.Global.Password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
		newAPIkey, err = auth.ServerLogin(config.Global.Username, config.Global.Password)
		if err != nil {
			log.Fatalf("Unable to connect to server, exiting.")
			os.Exit(1)
		}
		err = config.SetAPIKey(newAPIkey)
		if err != nil {
			log.Fatalf("Fail to set api key")
		}

		globalPubKey, globalPrivKey, err = auth.GeneratePublicKey()
		if err != nil {
			fmt.Println(err)
			return
		}

		// stateful global keys
		config.Global.GlobalPrivKey = globalPrivKey
		config.Global.GlobalPubKey = globalPubKey

		err = auth.RegisterPublicKeyWithServer(config.Global.Username, globalPubKey)
		if err != nil {
			fmt.Println("Unable to register public key with server, exiting.")
			os.Exit(1)
		}

		newC2Bytes, decryptedByte, err := decryptInterceptMessage(message.Payload, config.Global.Username, victimName, c2Bytes, crcC2Bytes)
		if err != nil {
			fmt.Println("An error occured while encrypting message.", err)
		}
		c2Bytes = newC2Bytes
		decryptedMessage = decryptedMessage + decryptedByte
		fmt.Printf("decrypted message: %s\n", decryptedMessage)
	}
	return decryptedMessage, err
}

func decryptInterceptMessage(payload string, senderUsername string, victimName string, c2Bytes []byte, crcC2Bytes []byte) (newC2Bytes []byte, decryptedByte string, err error) {
	// TODO: IMPLEMENT

	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Fatalf("Error base64 decoding payload: %v", err)
		return nil, "", err
	}

	var ciphertext config.CiphertextStruct

	err = json.Unmarshal([]byte(payloadBytes), &ciphertext)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	fmt.Printf("origin c2Bytes  : %+v\n", c2Bytes)

	modifiedCrcC2Bytes := make([]byte, len(crcC2Bytes))
	copy(modifiedCrcC2Bytes, c2Bytes)

	a := byte('a')
	colon := byte(':')
	x := colon ^ a
	oracleByte := c2Bytes[len(senderUsername)-1] ^ byte(x)
	fmt.Printf("oracleByte      : %+v\n", oracleByte)

	// modifiedC2Bytes := make([]byte, len(c2Bytes))
	// copy(modifiedC2Bytes, c2Bytes)
	modifiedC2Bytes := append(c2Bytes[:len(senderUsername)-1], oracleByte)
	fmt.Printf("modifiedC2Bytes : %+v\n", modifiedC2Bytes)

	modifiedC2Bytes = append(modifiedC2Bytes, c2Bytes[len(senderUsername):]...)

	fmt.Printf("modifiedC2Bytes : %+v\n", modifiedC2Bytes)

	// guessing delimiter
	toGuess := modifiedC2Bytes[len(senderUsername)]

	for i := 0; i <= 0x7F; i++ {
		guessed := toGuess ^ byte(i)
		modifiedC2Bytes[len(senderUsername)] = guessed

		// CRC B
		deltaBytes := make([]byte, len(c2Bytes))
		deltaBytes[len(senderUsername)-1] = x
		// deltaBytes[len(senderUsername)] = byte(i)
		deltaBytes[len(senderUsername)] = byte(i)
		fmt.Printf("mod deltaBytes: %x\n", deltaBytes)
		// crcB := crc32.ChecksumIEEE(deltaBytes)

		// akash method
		finalModifiedC2Bytes := FixCRC(modifiedCrcC2Bytes, deltaBytes)
		fmt.Printf("finalModifiedC2Bytes:  %x\n", finalModifiedC2Bytes)
		//

		modifiedC2String := base64.StdEncoding.EncodeToString(finalModifiedC2Bytes)

		toSign := ciphertext.C1 + modifiedC2String
		privKey := config.Global.GlobalPrivKey
		sigBytes := ECDSASign([]byte(toSign), privKey)

		// Encode the resulting signature using BASE64
		sig := base64.StdEncoding.EncodeToString(sigBytes)

		modifiedPayload := config.CiphertextStruct{
			C1:  ciphertext.C1,
			C2:  modifiedC2String,
			Sig: sig,
		}

		modifiedPayloadBytes, err := json.Marshal(modifiedPayload)
		if err != nil {
			log.Fatalf("Error signing the message: %v", err)
		}

		// Print the result
		SendMessageToServer(config.Global.Username, victimName, []byte(modifiedPayloadBytes), 0)

		// sleep and get read receipt
		time.Sleep(3 * time.Duration(100) * time.Millisecond)
		readReceipt, _ := GetMessagesFromServer()

		for f := 0; f < len(readReceipt); f++ {
			message := readReceipt[f]
			fmt.Printf("read receipt: %v\n", message.ReceiptID)
			if readReceipt[0].ReceiptID > -1 {
				fmt.Printf("guessed:       %x\n", guessed)
				correctGuess := byte(i) ^ byte(':')
				decryptedByte = string(correctGuess)
				fmt.Printf("decryptedByte: %s\n", decryptedByte)
				return modifiedC2Bytes, decryptedByte, err
			}
		}
	}

	return nil, "", err
}

// charlie || : || hi\n || crc
func FixCRC(c2Ciphertext []byte, XoringB []byte) []byte {

	modifiedCiphertext := make([]byte, len(c2Ciphertext))

	copy(modifiedCiphertext, c2Ciphertext)

	//XOR modifiedCiphertext except the last 4 bytes with XOringB

	// XOR modifiedCiphertext except the last 4 bytes with XoringB
	for i := 0; i < len(modifiedCiphertext)-4; i++ {
		modifiedCiphertext[i] ^= XoringB[i]
	}

	// Calculate the CRC32 checksum of the original plaintext CRC(A)
	crc32Original := binary.LittleEndian.Uint32(c2Ciphertext[len(c2Ciphertext)-4:])

	// Calculate the CRC32 checksum of the modifiemodifiedc2d ciphertext CRC(B)

	crc32Modified := crc32.ChecksumIEEE(XoringB)

	// CRC(0) checksum

	hex := make([]byte, len(c2Ciphertext)-4)
	for i := range hex {
		hex[i] = 0x00
	}

	checksum_zero := crc32.ChecksumIEEE(hex)

	// XOR the original CRC32 checksum with the modified CRC32 checksum CRC(0) XOR CRC(A) COR CRC(B)
	crc32New := crc32Original ^ crc32Modified ^ checksum_zero

	// Update the last 4 bytes of the modified ciphertext with the new CRC32 checksum
	binary.LittleEndian.PutUint32(modifiedCiphertext[len(modifiedCiphertext)-4:], crc32New)

	return modifiedCiphertext
}

func readInterceptedMessage(filePath string) (message config.MessageStruct, err error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Decode the JSON data from the file
	err = json.NewDecoder(file).Decode(&message)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	return
}
