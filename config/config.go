package config

import (
	"crypto/tls"
	"flag"
	"fmt"

	"net/http"
	"strconv"
)

// Config holds the configuration settings derived from command line arguments.
type Config struct {
	ServerPort          int
	ServerDomain        string
	ServerDomainAndPort string
	ServerProtocol      string
	Username            string
	Password            string
	ApiKey              string
	AttachmentsDir      string
	NoTLS               bool
	StrictTLS           bool
	DoUserRegister      bool
	HeadlessMode        bool
	MessageIDCounter    int
	GlobalPubKey        PubKeyStruct
	GlobalPrivKey       PrivKeyStruct
}

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	Decrypted string `json:"decrypted"`
	Url       string `json:"url"`
	LocalPath string `json:"localpath"`
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}

var Global *Config
var ApiKey *APIKeyStruct

// NewConfig parses command line arguments and returns a new Config.
func InitConfig() (err error) {
	Global = new(Config)

	flag.IntVar(&Global.ServerPort, "port", 8080, "port for the server")
	flag.StringVar(&Global.ServerDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&Global.Username, "username", "alice", "login username")
	flag.StringVar(&Global.Password, "password", "abc", "login password")
	flag.StringVar(&Global.AttachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&Global.NoTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&Global.StrictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&Global.DoUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&Global.HeadlessMode, "headless", false, "run in headless mode")

	flag.Parse()

	// Set the server protocol to http or https
	if Global.NoTLS == false {
		Global.ServerProtocol = "https"
	} else {
		Global.ServerProtocol = "http"
	}

	if Global.StrictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	Global.ServerDomainAndPort = Global.ServerDomain + ":" + strconv.Itoa(Global.ServerPort)

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if Global.StrictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// // Set up the server domain and port

	return
}

func SetAPIKey(apiKey string) (err error) {
	ApiKey = new(APIKeyStruct)
	ApiKey.APIkey = apiKey
	return
}
