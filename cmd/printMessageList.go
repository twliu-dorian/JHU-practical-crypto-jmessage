package cmd

import (
	"fmt"
	"jmessage_2024/config"
)

func PrintMessageList(messageArray []config.MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {

		fmt.Printf("From: %s\n\n", messageArray[i].From)
		if messageArray[i].Payload == "" {
			fmt.Printf("Read receipt, receipt id: %d\n", messageArray[i].ReceiptID)
		} else {
			fmt.Printf(messageArray[i].Decrypted)
			fmt.Println("message local path", messageArray[i].LocalPath)
			if messageArray[i].LocalPath != "" {
				fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].LocalPath)
			} else if messageArray[i].Url != "" {
				fmt.Printf("\n\tAttachment download failed\n")
			}
		}

		fmt.Printf("\n-----------------------------\n\n")
	}
}
