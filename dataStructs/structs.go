package dataStructs

import (
	"crypto/rsa"
)

type Data struct {
	UserData    User
	ProductData Product
}

type Message struct {
	Body []byte
}

type User struct {
	Login      string
	Password   string
	Userkey    rsa.PublicKey
	ServerKey  rsa.PublicKey
	SessionKey []byte
}

func (user *User) ToMap() map[string]string {
	return map[string]string{
		"Login":    user.Login,
		"Password": user.Password,
	}
}

type Product struct {
	Name        string
	Price       string
	Description string
}

func (p *Product) checkProduct() bool {
	test := false
	if p.Name != "" && p.Price != "" {
		test = true
	}
	return test
}
