package cmd

import (
	"encoding/json"
	"fmt"
	"jmessage_2024/config"
	"log"
	"os"
)

func DecryptMessages(messageArray []config.MessageStruct) {
	// TODO: IMPLEMENT
	for i := 0; i < len(messageArray); i++ {
		message := messageArray[i]
		fileContent, err := os.ReadFile("cred/globalKeys.json")
		if err != nil {
			log.Fatalf("Error read file error: %v", err)
			return
		}

		var privKey *config.PrivKeyStruct
		err = json.Unmarshal(fileContent, &privKey)
		if err != nil {
			log.Fatalf("Error unmarshal privatekey error: %v", err)
			return
		}

		pubKey, err := GetPublicKeyFromServer(message.From)
		if err != nil {
			fmt.Printf("Could not obtain public key for user %s.\n", message.From)
			return
		}

		// var messageJson config.MessageStruct
		payloadBytes, err := DecryptMessage(message.Payload, message.From, pubKey, privKey)
		if err != nil {
			log.Fatalf("Fail to decrypt message %s.\n", message.From)
			return
		}
		messageArray[i].Decrypted = string(payloadBytes)
		fmt.Println("decrypted message:", messageArray[i].Decrypted)
		// if err := json.Unmarshal(res, &messageJson); err != nil { // Parse []byte to go struct pointer
		// 	fmt.Println("Can not unmarshal JSON")
		// }

	}
}
