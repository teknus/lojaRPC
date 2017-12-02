package main

import (
	"crypto/rsa"
	"net/rpc"
)

type Loja struct {
	privateKey      rsa.PrivateKey
	publicKey       rsa.PublicKey
	users           map[string]string
	usersKey        map[string]rsa.PublicKey
	usersSessionKey map[string][]byte
	products        map[string]data.Product
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