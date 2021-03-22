package auth

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"time"
)

func CreateToken(key *rsa.PrivateKey, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(expiresIn).Unix(),
		IssuedAt:  time.Now().Unix(),
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
