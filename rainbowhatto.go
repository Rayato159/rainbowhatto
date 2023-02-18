package rainbowhatto

import (
	"errors"
	"fmt"

	"github.com/Rayato159/rainbowhatto/src"
	"github.com/golang-jwt/jwt/v4"
)

// Sign algorithm
func HMAC() src.SignAlgorithm {
	return src.HMAC
}
func RSA() src.SignAlgorithm {
	return src.RSA
}

type Config struct {
	// The secret that means a file of .pem key or key in dicectly
	ExpiresAt int64  // Required
	Secret    string // Required
	Claims    any    // Optional
}

type rainbow struct {
	// The secret that means a file of .pem key or key in dicectly
	src.Token
}

// RSAToken Concrete
type rsaToken struct {
	src.Token
}

func newRSAToken(rw rainbow) src.IToken {
	return &rsaToken{
		Token: src.Token{
			SignAlgorithm: rw.Token.GetSignAlgorithm(),
			ExpiresAt:     rw.Token.GetExpiresAt(),
			Key: &src.Key{
				PrivateKey: rw.Token.Key.GetPrivateKey(),
			},
			Claims: rw.Token.GetClaims(),
		},
	}
}

type hmacToken struct {
	src.Token
}

// HMAC Concrete
func newHMACToken(rw rainbow) src.IToken {
	return &hmacToken{
		Token: src.Token{
			SignAlgorithm: rw.Token.GetSignAlgorithm(),
			ExpiresAt:     rw.Token.GetExpiresAt(),
			Key: &src.Key{
				CommonKey: rw.Token.Key.GetCommonKey(),
			},
			Claims: rw.Token.GetClaims(),
		},
	}
}

type parseToken struct {
	src.Token
}

// Factory
func BuildToken(alg src.SignAlgorithm, cfg Config) src.IToken {
	rw := rainbow{
		src.Token{
			SignAlgorithm: alg,
			ExpiresAt:     &jwt.NumericDate{},
			Claims:        &src.NewClaims{},
			Key:           &src.Key{},
		},
	}
	rw.Token.SetExpiresAt(cfg.ExpiresAt)
	rw.Token.SetSecret(cfg.Secret)
	rw.Token.SetClaims(cfg.Claims)

	switch alg {
	case src.HMAC:
		return newHMACToken(rw)
	case src.RSA:
		return newRSAToken(rw)
	default:
		panic("init token error")
	}
}

type Claims struct {
	*src.NewClaims `json:"claims"`
}

func ReverseHMACToken(token string, secret string) (*Claims, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &src.NewClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("error, unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, fmt.Errorf("token format is invalid")
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token had expired")
		} else {
			return nil, fmt.Errorf("parse token error: %v", err)
		}
	}

	if claims, ok := parsedToken.Claims.(*src.NewClaims); ok && parsedToken.Valid {
		return &Claims{claims}, nil
	}
	return nil, fmt.Errorf("claims type error")
}

func ReverseRSAToken(token string, path string) (*Claims, error) {
	type tempKey struct {
		src.Key
	}
	key := new(tempKey)
	key.Key.SetPublicKey(path)

	parsedToken, err := jwt.ParseWithClaims(token, &src.NewClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("error, unexpected signing method: %v", token.Header["alg"])
		}
		return key.Key.GetPublicKey(), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, fmt.Errorf("token format is invalid")
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token had expired")
		} else {
			return nil, fmt.Errorf("parse token error: %v", err)
		}
	}

	if claims, ok := parsedToken.Claims.(*src.NewClaims); ok && parsedToken.Valid {
		return &Claims{claims}, nil
	}
	return nil, fmt.Errorf("claims type error")
}
