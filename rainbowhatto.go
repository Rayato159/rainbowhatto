package rainbowhatto

import (
	"errors"
	"fmt"

	"github.com/Rayato159/rainbowhatto/src"
	"github.com/golang-jwt/jwt/v4"
)

type Algorithm string

const (
	HMAC Algorithm = "HMAC"
	RSA  Algorithm = "RSA"
)

type Config struct {
	// The secret that means a file of .pem key or key in dicectly
	ExpiresAt int64  // Required
	Secret    string // Required
	Claims    any    `json:"claims"` // Optional
}

type rainbow struct {
	// The secret that means a file of .pem key or key in dicectly
	ExpiresAt src.IToken // Required
	Secret    src.IToken // Required
	Claims    src.IToken // Optional
	src.Token
}

// RSAToken Concrete
type rsaToken struct {
	src.Token
}

func newRSAToken(rw *rainbow) src.IToken {
	return &rsaToken{
		Token: src.Token{
			SignAlgorithm: src.RSA,
			ExpiresAt:     rw.GetExpiresAt(),
			Key: &src.Key{
				PrivateKey: rw.Key.GetPrivateKey(),
				PublicKey:  rw.Key.GetPublicKey(),
			},
			Claims: rw.GetClaims(),
		},
	}
}

type hmacToken struct {
	src.Token
}

// HMAC Concrete
func newHMACKToken(rw *rainbow) src.IToken {
	return &hmacToken{
		Token: src.Token{
			SignAlgorithm: src.HMAC,
			ExpiresAt:     rw.GetExpiresAt(),
			Key: &src.Key{
				CommonKey: rw.Key.GetCommonKey(),
			},
			Claims: rw.GetClaims(),
		},
	}
}

type parseToken struct {
	src.Token
}

// Factory
func BuildToken(tt Algorithm, cfg Config) (src.IToken, error) {
	rw := new(rainbow)
	rw.ExpiresAt.SetExpiresAt(cfg.ExpiresAt)
	rw.Secret.SetSecret(cfg.Secret)
	rw.Claims.SetClaims(cfg.Claims)

	switch tt {
	case HMAC:
		return newHMACKToken(rw), nil
	case RSA:
		return newRSAToken(rw), nil
	}
	return nil, fmt.Errorf("init token error")
}

type Claims struct {
	*src.NewClaims
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
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token had expired")
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
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token had expired")
		}
	}

	if claims, ok := parsedToken.Claims.(*src.NewClaims); ok && parsedToken.Valid {
		return &Claims{claims}, nil
	}
	return nil, fmt.Errorf("claims type error")
}
