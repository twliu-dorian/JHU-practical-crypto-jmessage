package cmd

import (
	"fmt"
	"jmessage_2024/config"
	"log"
)

func DecryptMessages(messageArray []config.MessageStruct) {
	// TODO: IMPLEMENT
	for i := 0; i < len(messageArray); i++ {
		message := messageArray[i]

		if messageArray[i].Payload != "" {
			pubKey, err := GetPublicKeyFromServer(message.From)
			if err != nil {
				fmt.Printf("Could not obtain public key for user %s.\n", message.From)
				return
			}

			// var messageJson config.MessageStruct
			payloadBytes, err := DecryptMessage(message.Payload, message.From, pubKey, &config.Global.GlobalPrivKey)
			if err != nil {
				log.Fatalf("Fail to decrypt message %s.\n", message.From)
				return
			}

			if payloadBytes == nil {
				return
			} else {
				messageArray[i].Decrypted = string(payloadBytes)

				// add decrypt attachment if message is a "url||key||hash"
				message.ReceiptID = config.Global.MessageIDCounter
				err = SendMessageToServer(config.Global.Username, message.From, nil, message.ReceiptID)
				if err != nil {
					log.Fatalf("Fail to send receicpt %d of message %s .\n", message.ReceiptID, messageArray[i].Decrypted)
					return
				}
			}
		}
	}
}
