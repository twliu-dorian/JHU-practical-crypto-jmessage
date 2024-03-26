package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"jmessage_2024/config"
)

func DownloadAttachments(messageArray []config.MessageStruct) {
	if len(messageArray) == 0 {
		return
	}
	downloadFolder := config.Global.AttachmentsDir + "/decryptedPlain"
	if _, err := os.Stat(downloadFolder); os.IsNotExist(err) {
		// Folder does not exist, so create it
		err := os.MkdirAll(downloadFolder, 0755) // Use appropriate permissions
		if err != nil {
			log.Fatalf("Failed to create folder: %v", err)
		}
	}

	pattern := `>>>MSGURL=([^?]+)\?KEY=([^?]+)\?H=([^=]+=)`
	re := regexp.MustCompile(pattern)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {

		message := messageArray[i].Decrypted
		matches := re.FindStringSubmatch(message)
		if matches != nil && len(matches) > 0 {
			messageArray[i].Url = matches[1]
			// Make a random filename
			randBytes := make([]byte, 16)
			if _, err := rand.Read(randBytes); err != nil {
				fmt.Println("Error generating random bytes:", err)
				continue // Skip this iteration
			}

			localPath := filepath.Join(downloadFolder, "/"+"attachment_"+hex.EncodeToString(randBytes)+".dat")

			err := DownloadFileFromServer(messageArray[i].Url, localPath)
			if err == nil {
				messageArray[i].LocalPath = localPath
				fmt.Println("assigned local path", messageArray[i].LocalPath)
			} else {
				fmt.Println(err)
			}
		}
	}
}
