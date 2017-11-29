package dataStructs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"io"
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

const symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_!@#$%*"

func SessionKey() []byte {
	n := 32
	output := make([]byte, n)
	randomness := make([]byte, n)
	_, err := rand.Read(randomness)
	if err != nil {
		panic(err)
	}
	for pos := range output {
		random := uint8(randomness[pos])
		randomPos := random % uint8(len(symbols))
		output[pos] = symbols[randomPos]
	}

	return output
}

func Encrypt(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext
}

func Decrypt(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}
