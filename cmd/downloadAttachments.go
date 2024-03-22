package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"jmessage_2024/config"
)

func DownloadAttachments(messageArray []config.MessageStruct) {
	if len(messageArray) == 0 {
		return
	}

	os.Mkdir(config.Global.AttachmentsDir, 0755)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].Url != "" {
			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(config.Global.AttachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

			err := DownloadFileFromServer(messageArray[i].Url, localPath)
			if err == nil {
				messageArray[i].LocalPath = localPath
			} else {
				fmt.Println(err)
			}
		}
	}
}
