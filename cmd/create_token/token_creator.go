package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/plally/vulpes_authenticator/auth"
	"log"
	"time"
)

var pkeyFilename = flag.String("pkey", "", "private key to sign created token with")
var subject = flag.String("sub", "", "claims subject")

func main() {
	flag.Parse()

	pkey, err := auth.ReadPrivateKey(*pkeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	token, err := CreateToken(pkey, time.Hour*24*30)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)

}

func CreateToken(key *rsa.PrivateKey, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(expiresIn).Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   *subject,
	})

	return token.SignedString(key)
}

func ValidateToken(key *rsa.PublicKey, tokenString string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return false, err
	}

	return token.Valid && token.Claims.Valid() == nil, nil
}
