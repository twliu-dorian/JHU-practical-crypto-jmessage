package main

import (
	"bufio"
	"encoding/json"
	"fmt"

	"os"
	"strings"
	"time"

	"jmessage_2024/auth"
	"jmessage_2024/cmd"
	"jmessage_2024/config"
)

// Globals

// var (
// serverPort          int
// serverDomain        string
// serverDomainAndPort string
// serverProtocol      string
// noTLS               bool
// strictTLS           bool
// username            string
// password            string
// apiKey string
// doUserRegister   bool
// headlessMode     bool
// messageIDCounter int
// attachmentsDir      string
// globalPubKey  cmd.PubKeyStruct
// globalPrivKey cmd.PrivKeyStruct
// )

// type FilePathStruct struct {
// 	Path string `json:"path"`
// }

// type APIKeyStruct struct {
// 	APIkey string `json:"APIkey"`
// }

// type UserStruct struct {
// 	Username     string `json:"username"`
// 	CreationTime int    `json:"creationTime"`
// 	CheckedTime  int    `json:"lastCheckedTime"`
// }

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
// func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
// 	// Initialize a client
// 	client := &http.Client{}
// 	log.Printf("Request body: %s\n", string(postContents))
// 	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
// 	if err != nil {
// 		return 0, nil, err
// 	}

// 	// Set up some fake headers
// 	req.Header = http.Header{
// 		"Content-Type": {"application/json"},
// 		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
// 	}

// 	// Make the POST request
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return 0, nil, err
// 	}

// 	// Extract the body contents
// 	defer resp.Body.Close()
// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return 0, nil, err
// 	}

// 	return resp.StatusCode, body, nil
// }

// Do a GET request and return the result
// func doGetRequest(getURL string) (int, []byte, error) {
// 	// Initialize a client
// 	client := &http.Client{}
// 	req, err := http.NewRequest("GET", getURL, nil)
// 	if err != nil {
// 		return 0, nil, err
// 	}

// 	// Set up some fake headers
// 	req.Header = http.Header{
// 		"Content-Type": {"application/json"},
// 		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
// 	}

// 	// Make the GET request
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		fmt.Println(err)
// 		return 0, nil, err
// 	}

// 	// Extract the body contents
// 	defer resp.Body.Close()
// 	body, err := io.ReadAll(resp.Body)

// 	return resp.StatusCode, body, nil
// }

// Upload a file to the server
// func uploadFileToServer(filename string) (string, error) {
// 	file, err := os.Open(filename)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer file.Close()

// 	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
// 		username + "/" + apiKey

// 	body := &bytes.Buffer{}
// 	writer := multipart.NewWriter(body)
// 	part, _ := writer.CreateFormFile("filefield", filename)
// 	io.Copy(part, file)
// 	writer.Close()

// 	r, _ := http.NewRequest("POST", posturl, body)
// 	r.Header.Set("Content-Type", writer.FormDataContentType())
// 	client := &http.Client{}
// 	resp, err := client.Do(r)
// 	defer resp.Body.Close()

// 	// Read the response body
// 	respBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		// Handle error
// 		fmt.Println("Error while reading the response bytes:", err)
// 		return "", err
// 	}

// 	// Unmarshal the JSON into a map or a struct
// 	var resultStruct FilePathStruct
// 	err = json.Unmarshal(respBody, &resultStruct)
// 	if err != nil {
// 		// Handle error
// 		fmt.Println("Error while parsing JSON:", err)
// 		return "", err
// 	}

// 	// Construct a URL
// 	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
// 		resultStruct.Path

// 	return fileURL, nil
// }

// // Download a file from the server and return its local path
// func downloadFileFromServer(geturl string, localPath string) error {
// 	// Get the file data
// 	resp, err := http.Get(geturl)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	// no errors; return
// 	if resp.StatusCode != 200 {
// 		return errors.New("Bad result code")
// 	}

// 	// Create the file
// 	out, err := os.Create(localPath)
// 	if err != nil {
// 		return err
// 	}
// 	defer out.Close()

// 	// Write the body to file
// 	_, err = io.Copy(out, resp.Body)
// 	return err
// }

// // Log in to server
// func serverLogin(username string, password string) (string, error) {
// 	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
// 		username + "/" + password

// 	code, body, err := api.DoGetRequest(geturl)
// 	if err != nil {
// 		return "", err
// 	}
// 	if code != 200 {
// 		return "", errors.New("Bad result code")
// 	}

// 	// Parse JSON into an APIKey struct
// 	var result APIKeyStruct
// 	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
// 		fmt.Println("Can not unmarshal JSON")
// 	}

// 	return result.APIkey, nil
// }

// // Log in to server
// func getPublicKeyFromServer(forUser string) (*cmd.PubKeyStruct, error) {
// 	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

// 	code, body, err := api.DoGetRequest(geturl)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if code != 200 {
// 		return nil, errors.New("Bad result code")
// 	}

// 	// Parse JSON into an PubKeyStruct
// 	var result cmd.PubKeyStruct
// 	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
// 		fmt.Println("Can not unmarshal JSON")
// 	}

// 	return &result, nil
// }

// // Register username with the server
// func registerUserWithServer(username string, password string) error {
// 	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
// 		username + "/" + password

// 	code, _, err := api.DoGetRequest(geturl)
// 	if err != nil {
// 		return err
// 	}

// 	if code != 200 {
// 		return errors.New("Bad result code")
// 	}

// 	return nil
// }

// // Get messages from the server
// func getMessagesFromServer() ([]cmd.MessageStruct, error) {
// 	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
// 		username + "/" + apiKey

// 	// Make the request to the server
// 	code, body, err := api.DoGetRequest(geturl)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if code != 200 {
// 		return nil, errors.New("Bad result code")
// 	}

// 	// Parse JSON into an array of MessageStructs
// 	var result []cmd.MessageStruct
// 	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
// 		fmt.Println("Can not unmarshal JSON")
// 	}

// 	// TODO: Implement decryption
// 	cmd.DecryptMessages(result)

// 	return result, nil
// }

// // Get messages from the server
// func getUserListFromServer() ([]UserStruct, error) {
// 	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

// 	// Make the request to the server
// 	code, body, err := api.DoGetRequest(geturl)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if code != 200 {
// 		return nil, errors.New("Bad result code")
// 	}

// 	// Parse JSON into an array of MessageStructs
// 	var result []UserStruct
// 	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
// 		fmt.Println("Can not unmarshal JSON")
// 	}

// 	// Sort the user list by timestamp
// 	sort.Slice(result, func(i, j int) bool {
// 		return result[i].CheckedTime > result[j].CheckedTime
// 	})

// 	return result, nil
// }

// // Post a message to the server
// func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
// 	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
// 		username + "/" + apiKey

// 	// Format the message as a JSON object and increment the message ID counter
// 	msg := cmd.MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}
// 	messageIDCounter++

// 	body, err := json.Marshal(msg)
// 	if err != nil {
// 		return err
// 	}

// 	// Post it to the server
// 	code, _, err := api.DoPostRequest(posturl, body)
// 	if err != nil {
// 		return err
// 	}

// 	if code != 200 {
// 		return errors.New("Bad result code")
// 	}

// 	return nil
// }

// // Read in a message from the command line and then send it to the serve
// func doReadAndSendMessage(recipient string, messageBody string) error {
// 	keepReading := true
// 	reader := bufio.NewReader(os.Stdin)

// 	// First, obtain the recipient's public key
// 	pubkey, err := getPublicKeyFromServer(recipient)
// 	if err != nil {
// 		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
// 		return err
// 	}

// 	// If there is no message given, we read one in from the user
// 	if messageBody == "" {
// 		// Next, read in a multi-line message, ending when we get an empty line (\n)
// 		fmt.Println("Enter message contents below. Finish the message with a period.")

// 		for keepReading == true {
// 			input, err := reader.ReadString('\n')
// 			if err != nil {
// 				fmt.Println("An error occured while reading input. Please try again", err)
// 			}

// 			if strings.TrimSpace(input) == "." {
// 				keepReading = false
// 			} else {
// 				messageBody = messageBody + input
// 			}
// 		}
// 	}

// 	// Now encrypt the message
// 	fmt.Println("\n\n", &globalPrivKey, "\n\n")
// 	encryptedMessage, err := cmd.EncryptMessage([]byte(messageBody), username, pubkey)
// 	if err != nil {
// 		fmt.Println("An error occured while encrypting message.", err)
// 	}

// 	// Finally, send the encrypted message to the server
// 	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
// }

// // Request a key from the server
// func getKeyFromServer(user_key string) {
// 	geturl := serverProtocol + "://" + serverDomain + ":" + strconv.Itoa(serverPort) + "/lookupKey?" + user_key

// 	fmt.Println(geturl)
// }

// // Upload a new public key to the server
// func registerPublicKeyWithServer(username string, pubKeyEncoded cmd.PubKeyStruct) error {
// 	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
// 		username + "/" + apiKey

// 	body, err := json.Marshal(pubKeyEncoded)
// 	if err != nil {
// 		return err
// 	}

// 	// Post it to the server
// 	code, _, err := api.DoPostRequest(posturl, body)
// 	if err != nil {
// 		return err
// 	}

// 	if code != 200 {
// 		return errors.New("Bad result code")
// 	}

// 	return nil
// }

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns the HEX encoded key
// and file hash, or an error.
// func encryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, string, error) {
// 	// TODO: IMPLEMENT
// 	return "", "", nil
// }

// func decodePrivateSigningKey(privKey PrivKeyStruct) ecdsa.PrivateKey {
// 	var result ecdsa.PrivateKey

// 	// TODO: IMPLEMENT

// 	return result
// }

// Sign a string using ECDSA
// func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
// 	// TODO: IMPLEMENT

// 	return nil
// }

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
// func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
// 	// TODO: IMPLEMENT

// 	return nil, nil
// }

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
// func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) []byte {
// 	// TODO: IMPLEMENT

// 	return nil
// }

// Decrypt a list of messages in place
// func decryptMessages(messageArray []MessageStruct) {
// 	// TODO: IMPLEMENT
// }

// Download any attachments in a message list
// func downloadAttachments(messageArray []cmd.MessageStruct) {
// 	if len(messageArray) == 0 {
// 		return
// 	}

// 	os.Mkdir(config.Global.AttachmentsDir, 0755)

// 	// Iterate through the array, checking for attachments
// 	for i := 0; i < len(messageArray); i++ {
// 		if messageArray[i].Url != "" {
// 			// Make a random filename
// 			randBytes := make([]byte, 16)
// 			rand.Read(randBytes)
// 			localPath := filepath.Join(config.Global.AttachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

// 			err := downloadFileFromServer(messageArray[i].Url, localPath)
// 			if err == nil {
// 				messageArray[i].LocalPath = localPath
// 			} else {
// 				fmt.Println(err)
// 			}
// 		}
// 	}
// }

// Print a list of message structs
// func printMessageList(messageArray []cmd.MessageStruct) {
// 	if len(messageArray) == 0 {
// 		fmt.Println("You have no new messages.")
// 		return
// 	}

// 	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
// 	// Iterate through the array, printing each message
// 	for i := 0; i < len(messageArray); i++ {
// 		if messageArray[i].ReceiptID != 0 {
// 			fmt.Printf("Read receipt\n")
// 			continue
// 		}

// 		fmt.Printf("From: %s\n\n", messageArray[i].From)

// 		fmt.Printf(messageArray[i].Decrypted)
// 		if messageArray[i].LocalPath != "" {
// 			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].LocalPath)
// 		} else if messageArray[i].Url != "" {
// 			fmt.Printf("\n\tAttachment download failed\n")
// 		}
// 		fmt.Printf("\n-----------------------------\n\n")
// 	}
// }

// Print a list of user structs
// func printUserList(userArray []UserStruct) {
// 	if len(userArray) == 0 {
// 		fmt.Println("There are no users on the server.")
// 		return
// 	}

// 	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

// 	// Get current Unix time
// 	timestamp := time.Now().Unix()

// 	// Iterate through the array, printing each message
// 	for i := 0; i < len(userArray); i++ {
// 		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
// 			fmt.Printf("* ")
// 		} else {
// 			fmt.Printf("  ")
// 		}

// 		fmt.Printf("%s\n", userArray[i].Username)
// 	}
// 	fmt.Printf("\n")
// }

// func getTempFilePath() string {
// 	randBytes := make([]byte, 16)
// 	rand.Read(randBytes)
// 	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
// }

// moved to cmd/generatePublickey.go
// Generate a fresh public key struct, containing encryption and signing keys
// func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
// 	var pubKey PubKeyStruct
// 	var privKey PrivKeyStruct

// 	// TODO: IMPLEMENT

// 	return pubKey, privKey, nil
// }

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	// flag.IntVar(&serverPort, "port", 8080, "port for the server")
	// flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	// flag.StringVar(&username, "username", "alice", "login username")
	// flag.StringVar(&password, "password", "abc", "login password")
	// flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	// flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	// flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	// flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	// flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	// flag.Parse()
	err := config.InitConfig()
	if err != nil {
		fmt.Println("Fail to init client")
		os.Exit(1)
	}

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
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	err = config.SetAPIKey(newAPIkey)
	// apiKey := config.APIKeyStruct{
	// 	APIkey: newAPIkey,
	// }
	// apiKeyJson, err := json.Marshal(apiKey)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// err = os.WriteFile("cred/apiKey.json", apiKeyJson, 0644)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// Geerate a fresh public key, then upload it to the server
	// var globalPubKey config.PubKeyStruct
	// var globalPrivKey config.PrivKeyStruct
	globalPubKey, globalPrivKey, err := auth.GeneratePublicKey()
	if err != nil {
		fmt.Println(err)
		return
	}

	// stateful global keys
	config.Global.GlobalPrivKey = globalPrivKey
	config.Global.GlobalPubKey = globalPubKey

	// Write JSON to file
	globalPrivKeyJson, err := json.Marshal(globalPrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = os.WriteFile("cred/globalKeys.json", globalPrivKeyJson, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

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
				fmt.Println("NOT IMPLEMENTED YET")
				// TODO: IMPLEMENT
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
