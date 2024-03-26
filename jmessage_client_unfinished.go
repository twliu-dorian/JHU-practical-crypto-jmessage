package main

import (
	"bufio"
	"fmt"
	"log"

	"os"
	"strings"
	"time"

	"jmessage_2024/auth"
	"jmessage_2024/cmd"
	"jmessage_2024/config"
)

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	err := config.InitConfig()
	if err != nil {
		fmt.Println("Fail to init client")
		os.Exit(1)
	}
	err = config.CreateFolders()

	// If we are registering a new username, let's do that first
	if config.Global.DoUserRegister == true {
		fmt.Println("Registering new user...")
		err := auth.RegisterUserWithServer(config.Global.Username, config.Global.Password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := auth.ServerLogin(config.Global.Username, config.Global.Password)
	if err != nil {
		log.Fatalf("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	err = config.SetAPIKey(newAPIkey)
	if err != nil {
		log.Fatalf("Fail to set api key")
		os.Exit(1)
	}

	globalPubKey, globalPrivKey, err := auth.GeneratePublicKey()
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
	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running == true {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if config.Global.HeadlessMode == false {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {
				err = cmd.DoReadAndSendMessage(strings.TrimSpace(parts[1]), "")
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := cmd.GetMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				cmd.DownloadAttachments(messageList)
				cmd.DecryptFileContent(messageList)
				cmd.PrintMessageList(messageList)
			}
		case "LIST":
			userList, err := cmd.GetUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				cmd.PrintUserList(userList)
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <username> <filename>")
			} else {
				plaintextFilePath := config.Global.AttachmentsDir + "/plain/" + strings.TrimSpace(parts[2])
				ciphertextFilePath := config.Global.AttachmentsDir + "/cipher/" + strings.TrimSpace(parts[2])
				recipient := strings.TrimSpace(parts[1])
				base64Key, base64FileHash, err := cmd.EncryptAttachment(plaintextFilePath, ciphertextFilePath)
				if err != nil {
					fmt.Printf("encrypt attachment error")
					return
				}

				tmpUrl, err := cmd.UploadFileToServer(ciphertextFilePath)
				if err != nil {
					fmt.Printf("Could not upload cipher file to server.\n")
					return
				}
				fmt.Println("tmpUrl", tmpUrl)

				message := fmt.Sprintf(">>>MSGURL=%s?KEY=%s?H=%s", tmpUrl, base64Key, base64FileHash)
				pubkey, err := cmd.GetPublicKeyFromServer(recipient)
				if err != nil {
					fmt.Printf("Could not obtain public key for user.\n")
					return
				}
				messageByte := []byte(message)
				encryptedMessage, err := cmd.EncryptMessage(messageByte, config.Global.Username, pubkey)
				if err != nil {
					fmt.Println("An error occured while encrypting message.", err)
				}

				// Finally, send the encrypted message to the server
				cmd.SendMessageToServer(config.Global.Username, recipient, []byte(encryptedMessage), 0)
			}
		case "FP":
			fingerprint, err := cmd.ComputeFingerPrint(strings.TrimSpace(parts[1]))
			if err != nil {
				fmt.Println("An error occured while getting fingerprint", err)
			} else {
				fmt.Printf("%s's public key fingerprint is: %s\n", strings.TrimSpace(parts[1]), fingerprint)
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command\n")
		}
	}
}
