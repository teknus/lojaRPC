package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/rpc"
	"os"

	data "github.com/teknus/lojaRPC/dataStructs"
)

type Loja struct {
	privateKey      rsa.PrivateKey
	publicKey       rsa.PublicKey
	users           map[string]string
	usersKey        map[string]rsa.PublicKey
	usersSessionKey map[string][]byte
	products        map[string]data.Product
}

// func getDataAsymmetric(loja *Loja, body []byte) data.Data {
// 	var data data.Data
// 	msgDec, _ := rsa.DecryptPKCS1v15(rand.Reader, &loja.privateKey, body)
// 	_ = json.Unmarshal(msgDec, &data)
// 	return data
// }

// func getData(loja *Loja, body []byte) data.Data {
// 	var data data.Data
// 	msgDec := decrypt(loja.sessionKey, body)
// 	_ = json.Unmarshal(msgDec, &data)
// 	return data
// }

func (loja *Loja) GetPublicKey(msg *map[string]rsa.PublicKey, reply *rsa.PublicKey) error {
	for key, value := range *msg {
		loja.usersKey[key] = value
	}
	*reply = loja.publicKey
	return nil
}

func (loja *Loja) Login(msg *[]byte, reply *[]byte) error {
	var user map[string]string
	dmsg, _ := rsa.DecryptPKCS1v15(rand.Reader, &loja.privateKey, *msg)
	_ = json.Unmarshal(dmsg, &user)
	userKey := loja.usersKey[user["Login"]]
	loja.usersSessionKey[user["Login"]] = data.SessionKey()
	dmsg, _ = rsa.EncryptPKCS1v15(rand.Reader, &userKey, loja.usersSessionKey[user["Login"]])
	*reply = dmsg
	return nil
}

func (loja *Loja) CreateProduct(msg *map[string][]byte, reply *bool) error {
	var dmsg []byte
	var product data.Product
	var request map[string]string
	for key, value := range *msg {
		dmsg = data.Decrypt(loja.usersSessionKey[key], value)
		_ = json.Unmarshal(dmsg, &request)
		product = data.Product{Name: request["Name"], Price: request["Price"], Description: request["Description"]}
		for _, value := range loja.products {
			if value == product {
				*reply = false
				return nil
			}
		}
		*reply = true
	}
	if *reply {
		loja.products[product.Name] = product
	}
	fmt.Println(loja.products)
	return nil
}

// func (loja *Loja) UpdateProduct(msg *data.Message, reply *bool) error {
// 	data := getData(loja, msg.Body)
// 	*reply = true
// 	user, product := data.UserData, data.ProductData
// 	if loja.users[user.Login] == user.Password {
// 		for _, value := range loja.products {
// 			if value != product {
// 				*reply = false
// 			}
// 		}
// 		if *reply {
// 			loja.products[product.Name] = product
// 		}
// 	}
// 	return nil
// }

// func (loja *Loja) DeleteProduct(msg *data.Message, reply *bool) error {
// 	data := getData(loja, msg.Body)
// 	*reply = true
// 	user, product := data.UserData, data.ProductData
// 	if loja.users[user.Login] == user.Password {
// 		for _, value := range loja.products {
// 			if value != product {
// 				*reply = false
// 			}
// 		}
// 		if *reply {
// 			delete(loja.products, product.Name)
// 		}
// 	}
// 	return nil
// }

// func (loja *Loja) AllProduct(msg *data.Message, reply *data.Message) error {
// 	localData := getData(loja, msg.Body)
// 	user := localData.UserData
// 	if loja.users[user.Login] == user.Password {
// 		plaintext, _ := json.Marshal(loja.products)
// 		ciphertext := encrypt(localData.UserData.SessionKey, plaintext)
// 		reply.Body = ciphertext
// 	}
// 	return nil
// }

///login teknus 12345
func (loja *Loja) Teste(msg *[]byte, reply *data.Message) error {
	print(msg)
	dmsg, _ := rsa.DecryptPKCS1v15(rand.Reader, &loja.privateKey, *msg)
	reply.Body = dmsg
	return nil
}

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	loja := new(Loja)
	loja.privateKey = *key
	loja.usersKey = make(map[string]rsa.PublicKey)
	loja.users = make(map[string]string)
	loja.products = make(map[string]data.Product)
	loja.usersSessionKey = make(map[string][]byte)
	loja.publicKey = loja.privateKey.PublicKey
	loja.users["teknus"] = "12345"
	rpc.Register(loja)
	tcpAddr, err := net.ResolveTCPAddr("tcp", ":1234")
	checkError(err)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	fmt.Println("IIIIIH")
	for {
		conn, err := listener.Accept()
		if err == nil {
			rpc.ServeConn(conn)
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
