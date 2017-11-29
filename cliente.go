package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/rpc"
	"os"
	"strings"

	data "github.com/teknus/lojaRPC/dataStructs"
)

func readShell(toControl chan<- string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Shell")
	for {
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)
		toControl <- text
	}
	close(toControl)
}

func writeShell(fromControl <-chan string) {
	for text := range fromControl {
		fmt.Println(text)
	}
}

func toJson(user data.User, product data.Product) []byte {
	plaintext, _ := json.Marshal(data.Data{UserData: user, ProductData: product})
	return plaintext
}

func fromJson(ljson []byte) data.Data {
	var d data.Data
	_ = json.Unmarshal(ljson, &d)
	return d
}

const (
	create = 0
	update = 1
	login  = 2
	delete = 3
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ", os.Args[0], "server:port")
		os.Exit(1)
	}
	service := os.Args[1]
	client, _ := rpc.Dial("tcp", service)

	keyBoardInput := make(chan string)
	fromServer := make(chan string)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	user := new(data.User)
	user.Userkey = privateKey.PublicKey

	go readShell(keyBoardInput)
	go writeShell(fromServer)
	msgReply := new([]byte)
	for {
		select {
		case text := <-keyBoardInput:
			command := strings.Split(text, " ")
			switch c := command[0]; c {
			case "/login":
				if len(user.SessionKey) <= 0 {
					if len(command) == 3 {
						user.Login = command[1]
						user.Password = command[2]

						//Pegar Chave Publica do Servidor
						var reply rsa.PublicKey
						send := map[string]rsa.PublicKey{user.Login: user.Userkey}
						err := client.Call("Loja.GetPublicKey", send, &reply)
						user.ServerKey = reply

						if err != nil {
							fmt.Println("Error para pegar PublicKey no Server")
						}
						//Fazer Login e pegar chave de sessão hadoop jar /usr/lib/hadoop-2.8.2/share/hadoop/tools/lib/hadoop-streaming-2.8.2.jar -D mapred.map.tasks=4     -mapper mapper.py     -reducer reducer.py    -input wordcount/mobydick.txt     -output wordcount/output
						plainUser, _ := json.Marshal(user.ToMap())
						criptUser, _ := rsa.EncryptPKCS1v15(rand.Reader, &user.ServerKey, plainUser)
						_ = client.Call("Loja.Login", criptUser, msgReply)
						dmsg, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, *msgReply)
						user.SessionKey = dmsg
						if len(user.SessionKey) > 0 {
							fmt.Println("Login OK!")
						} else {
							fmt.Println("Error no Login")
						}
					}
				} else {
					fmt.Println("Voce já esta logado")
				}
			case "/create":
				fmt.Println("create")
			case "/update":
				fmt.Println("Update")
			case "/delete":
				fmt.Println("Delete")
			case "/list":
				fmt.Println("List")
			}
		}
	}
	//Fazer o menu do cliente
}
