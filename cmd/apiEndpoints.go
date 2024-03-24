package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"jmessage_2024/api"
	"jmessage_2024/config"
)

func UploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/uploadFile/" +
		config.Global.Username + "/" + config.ApiKey.APIkey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct config.FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func DownloadFileFromServer(geturl string, localPath string) error {
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("Bad result code")
	}

	// Create the file
	fmt.Println("downloading file to local", localPath)
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func GetPublicKeyFromServer(forUser string) (*config.PubKeyStruct, error) {
	geturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/lookupKey/" + forUser

	code, body, err := api.DoGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an PubKeyStruct
	var result config.PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Get messages from the server
func GetMessagesFromServer() ([]config.MessageStruct, error) {
	geturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/getMessages/" +
		config.Global.Username + "/" + config.ApiKey.APIkey

	// Make the request to the server
	code, body, err := api.DoGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []config.MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption
	DecryptMessages(result)

	return result, nil
}

// Get messages from the server
func GetUserListFromServer() (result []config.UserStruct, err error) {
	geturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := api.DoGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

// Post a message to the server
func SendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomainAndPort + "/sendMessage/" +
		config.Global.Username + "/" + config.ApiKey.APIkey

	// Format the message as a JSON object and increment the message ID counter
	msg := config.MessageStruct{sender, recipient, config.Global.MessageIDCounter, readReceiptID, base64.StdEncoding.EncodeToString(message), "", "", ""}
	config.Global.MessageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := api.DoPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the serve
func DoReadAndSendMessage(recipient string, messageBody string) error {
	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := GetPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading == true {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	// fmt.Println("\n\n", &config.GlobalPrivKey, "\n\n")
	encryptedMessage, err := EncryptMessage([]byte(messageBody), config.Global.Username, pubkey)
	if err != nil {
		fmt.Println("An error occured while encrypting message.", err)
	}

	// Finally, send the encrypted message to the server
	return SendMessageToServer(config.Global.Username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func GetKeyFromServer(user_key string) {
	geturl := config.Global.ServerProtocol + "://" + config.Global.ServerDomain + ":" + strconv.Itoa(config.Global.ServerPort) + "/lookupKey?" + user_key

	fmt.Println(geturl)
}
