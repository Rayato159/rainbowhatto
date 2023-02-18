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
	ExpiresAt int64 // Required
	HMAC      *HMACConfig
	RSA       *RSAConfig
	Claims    any // Optional
}

type RSAConfig struct {
	PrivateKey string // Required
	PublicKey  string // Required
}
type HMACConfig struct {
	Secret string // Required
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
func BuildToken(alg src.SignAlgorithm, cfg Config) (src.IToken, error) {
	rw := rainbow{
		src.Token{
			SignAlgorithm: alg,
			ExpiresAt:     &jwt.NumericDate{},
			Claims:        &src.NewClaims{},
			Key:           &src.Key{},
		},
	}
	rw.Token.SetExpiresAt(cfg.ExpiresAt)
	rw.Token.SetClaims(cfg.Claims)

	switch alg {
	case src.HMAC:
		// Error catcher
		if cfg.HMAC == nil {
			return nil, fmt.Errorf("hmac key is nil")
		}
		if cfg.HMAC.Secret == "" {
			return nil, fmt.Errorf("hmac key is missing")
		}
		// Sign
		rw.Token.SetSecret(cfg.HMAC.Secret)
		return newHMACToken(rw), nil
	case src.RSA:
		// Error catcher
		if cfg.RSA == nil {
			return nil, fmt.Errorf("rsa key is nil")
		}
		if cfg.RSA.PrivateKey == "" {
			return nil, fmt.Errorf("private key is missing")
		}
		// Sign
		rw.Token.SetSecret(cfg.RSA.PrivateKey)
		return newRSAToken(rw), nil
	default:
		return nil, fmt.Errorf("sign token error: unknown sign algorithm")
	}
}

func RefreshToken(alg src.SignAlgorithm, token string, cfg Config) (src.IToken, error) {
	rw := rainbow{
		src.Token{
			SignAlgorithm: alg,
			ExpiresAt:     &jwt.NumericDate{},
			Claims:        &src.NewClaims{},
			Key:           &src.Key{},
		},
	}

	switch alg {
	case src.HMAC:
		// Error catcher
		if cfg.HMAC == nil {
			return nil, fmt.Errorf("hmac key is nil")
		}
		if cfg.HMAC.Secret == "" {
			return nil, fmt.Errorf("hmac key is missing")
		}
		// Parse token
		claims, err := ReverseHMACToken(token, cfg.HMAC.Secret)
		if err != nil {
			return nil, err
		}
		// Set expires
		rw.Token.SetRepeatExpiresAt(claims.ExpiresAt.Unix())
		// Set secret
		rw.Token.SetSecret(cfg.HMAC.Secret)
		rw.Token.SetClaims(cfg.Claims)
		// Sign a new token
		return newHMACToken(rw), nil
	case src.RSA:
		// Error catcher
		if cfg.RSA == nil {
			return nil, fmt.Errorf("rsa key is nil")
		}
		if cfg.RSA.PrivateKey == "" {
			return nil, fmt.Errorf("private key is missing")
		}
		if cfg.RSA.PublicKey == "" {
			return nil, fmt.Errorf("public key is missing")
		}
		// Parse token
		claims, err := ReverseRSAToken(token, cfg.RSA.PublicKey)
		if err != nil {
			return nil, err
		}
		// Set expires
		rw.Token.SetRepeatExpiresAt(claims.ExpiresAt.Unix())
		// Set secret
		rw.Token.SetSecret(cfg.RSA.PrivateKey)
		rw.Token.SetClaims(cfg.Claims)
		// Sign a new token
		return newRSAToken(rw), nil
	default:
		return nil, fmt.Errorf("refresh token error: unknown sign algorithm")
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
