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

		DecryptMessage(message.Payload, message.From, pubKey, privKey)
	}
}
