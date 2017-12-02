package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"strings"

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

func (loja *Loja) GetPublicKey(msg *map[string]rsa.PublicKey, reply *rsa.PublicKey) error {
	for login, userKey := range *msg {
		if loja.users[login] != "" {
			loja.usersKey[login] = userKey
			*reply = loja.publicKey
		}
	}
	return nil
}

func (loja *Loja) Login(msg *[]byte, reply *[]byte) error {
	dmsg, _ := rsa.DecryptPKCS1v15(rand.Reader, &loja.privateKey, *msg)
	splitedmsg := strings.Split(string(dmsg[:len(dmsg)]), ":")
	for login, password := range loja.users {
		if login == splitedmsg[0] {
			if password == splitedmsg[1] {
				userKey := loja.usersKey[splitedmsg[0]]
				loja.usersSessionKey[splitedmsg[0]] = data.SessionKey()
				dmsg, _ = rsa.EncryptPKCS1v15(rand.Reader, &userKey, loja.usersSessionKey[splitedmsg[0]])
				*reply = dmsg
			}
		}
	}
	return nil
}

func (loja *Loja) CreateProduct(msg *map[string][]byte, reply *bool) error {
	var dmsg []byte
	var product data.Product
	for key, value := range *msg {
		dmsg = data.Decrypt(loja.usersSessionKey[key], value)
		splitedmsg := strings.Split(string(dmsg[:len(dmsg)]), ":")
		product = data.Product{Name: splitedmsg[0], Price: splitedmsg[1], Description: splitedmsg[2]}
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

func (loja *Loja) UpdateProduct(msg *map[string][]byte, reply *bool) error {
	var dmsg []byte
	var product data.Product
	*reply = false
	for key, value := range *msg {
		dmsg = data.Decrypt(loja.usersSessionKey[key], value)
		splitedmsg := strings.Split(string(dmsg[:len(dmsg)]), ":")
		product = data.Product{Name: splitedmsg[0], Price: splitedmsg[1], Description: splitedmsg[2]}
		_, ok := loja.products[splitedmsg[0]]
		if ok {
			loja.products[splitedmsg[0]] = product
		}
	}
	if *reply {
		loja.products[product.Name] = product
	}
	return nil
}

func (loja *Loja) DeleteProduct(msg *map[string][]byte, reply *bool) error {
	var dmsg []byte
	var tempMap map[string]data.Product
	for key, value := range *msg {
		dmsg = data.Decrypt(loja.usersSessionKey[key], value)
		splitedmsg := strings.Split(string(dmsg[:len(dmsg)]), ":")
		key := splitedmsg[0]
		//delete(loja.products, splitedmsg[0])
		for key, value := range loja.products {
			if key != splitedmsg[0] {
				tempMap[key] = value
			} else {
				*reply = true
			}
		}
		loja.products = tempMap
		fmt.Println(tempMap)
		if loja.products == nil {
			loja.products = make(map[string]data.Product)
		}
	}
	return nil
}

func (loja *Loja) AllProduct(msg *string, reply *[]byte) error {
	var r []byte
	for _, value := range loja.products {
		r = append(r, []byte(value.Name+":"+value.Price+":"+value.Description+";")...)
	}
	*reply = data.Encrypt(loja.usersSessionKey[*msg], r)
	return nil
}

func (loja *Loja) Find(msg *map[string][]byte, reply *[]byte) error {
	var r []byte
	for login, p := range *msg {
		dmsg := data.Decrypt(loja.usersSessionKey[login], p)
		product := strings.Split(string(dmsg[:len(dmsg)]), ":")
		for name, value := range loja.products {
			if name == product[0] {
				r = append(r, []byte(value.Name+":"+value.Price+":"+value.Description+";")...)
			}
		}
		*reply = data.Encrypt(loja.usersSessionKey[login], r)
	}
	return nil
}

///login teknus 12345

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
	tcpAddr, err := net.ResolveTCPAddr("tcp", ":9090")
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
