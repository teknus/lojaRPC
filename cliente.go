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
	var boolReply bool
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
						plainUser := []byte(user.Login + ":" + user.Password)
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
				if len(user.SessionKey) > 0 {
					if len(command) > 3 {
						p := []byte(command[1] + ":" + command[2] + ":" + strings.Join(command[3:], " "))
						encmp := data.Encrypt(user.SessionKey, p)
						createProduct := map[string][]byte{user.Login: encmp}
						_ = client.Call("Loja.CreateProduct", createProduct, &boolReply)
						if boolReply {
							fmt.Println("Criado com sucesso")
						} else {
							fmt.Println("Ocorreu um erro ao criar o produto ele pode já estar no banco")
						}
					} else {
						fmt.Println("Para criar um produto ")
						fmt.Println("   /create nomeDoProduto precoDoProduto descricaoDoProduto")
					}
				} else {
					fmt.Println("Acesso não autorizado")
				}
			case "/update":
				if len(user.SessionKey) > 0 {
					//Fazer uma busca na loja caso exista e a descrição ou o valor ou nome estaja vazio preencher
					p := []byte(command[1] + ":" + command[2] + ":" + strings.Join(command[3:], " "))
					encmp := data.Encrypt(user.SessionKey, p)
					createProduct := map[string][]byte{user.Login: encmp}
					_ = client.Call("Loja.CreateProduct", createProduct, &boolReply)
					if boolReply {
						fmt.Println("Criado com sucesso")
					} else {
						fmt.Println("Ocorreu um erro ao criar o produto ele pode já estar no banco")
					}
				} else {
					fmt.Println("Para atualizar um produto ")
					fmt.Println("   /update nomeDoProduto precoDoProduto descricaoDoProduto")
				}
			case "/delete":
				if len(user.SessionKey) > 0 {
					p := []byte(command[1] + ":")
					encmp := data.Encrypt(user.SessionKey, p)
					createProduct := map[string][]byte{user.Login: encmp}
					_ = client.Call("Loja.DeleteProduct", createProduct, &boolReply)
					if boolReply {
						fmt.Println("Deletou")
					} else {
						fmt.Println("Não existe")
					}
				} else {
					fmt.Println("Acesso não autorizado")
				}

			case "/find":
				if len(user.SessionKey) > 0 {
					p := []byte(command[1] + ":")
					encmp := data.Encrypt(user.SessionKey, p)
					createProduct := map[string][]byte{user.Login: encmp}
					_ = client.Call("Loja.Find", createProduct, msgReply)
					dec := data.Decrypt(user.SessionKey, *msgReply)
					fmt.Println(string(dec))

				} else {
					fmt.Println("Acesso não autorizado")
				}

			case "/list":
				if len(user.SessionKey) > 0 {
					_ = client.Call("Loja.AllProduct", user.Login, msgReply)
					decmsg := data.Decrypt(user.SessionKey, *msgReply)
					dmsg := string(decmsg)
					splitedmsg := strings.Split(string(dmsg[:len(dmsg)]), ";")
					for i := 0; i < len(splitedmsg)-1; i += 1 {
						line := strings.Split(splitedmsg[i], ":")
						fmt.Println("Nome do Produto: ", line[0])
						fmt.Println("Preço do Produto: ", line[1])
						fmt.Println("Descrição do Produto: ", line[2])
						fmt.Println("")
					}
				} else {
					fmt.Println("Acesso não autorizado")
				}
			}
		}
	}
	//Fazer o menu do cliente
}
