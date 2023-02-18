package src

import "github.com/golang-jwt/jwt/v4"

type SignAlgorithm jwt.SigningMethod

var (
	HMAC SignAlgorithm = jwt.SigningMethodHS256
	RSA  SignAlgorithm = jwt.SigningMethodRS256
)
