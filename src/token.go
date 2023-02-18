package src

import (
	"math"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/xid"
)

type IToken interface {
	SetSignAlgorithm(alg SignAlgorithm)
	SetExpiresAt(t int64)
	SetRepeatExpiresAt(t int64)
	SetSecret(secret string) IKey
	SetClaims(claims any)
	SignToken() string
	GetExpiresAt() *jwt.NumericDate
	GetClaims() *NewClaims
	GetSignAlgorithm() SignAlgorithm
}

type Token struct {
	SignAlgorithm SignAlgorithm
	ExpiresAt     *jwt.NumericDate
	Key           IKey
	Claims        *NewClaims `json:"claims"` // Payload
	Jwt           string     // Token in string
}

type NewClaims struct {
	Claims any `json:"claims"`
	jwt.RegisteredClaims
}

// Set
func (tk *Token) SetSignAlgorithm(alg SignAlgorithm) {}
func (tk *Token) SetExpiresAt(t int64) {
	tk.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Duration(t * int64(math.Pow10(9)))))
}
func (tk *Token) SetRepeatExpiresAt(t int64) {
	tk.ExpiresAt = jwt.NewNumericDate(time.Unix(t, 0))
}
func (tk *Token) SetSecret(secret string) IKey {
	switch tk.SignAlgorithm {
	case HMAC:
		tk.Key.SetCommonKey(secret)
		return tk.Key
	case RSA:
		tk.Key.SetPublicKey(secret)
		tk.Key.SetPrivateKey(secret)
		return tk.Key
	default:
		panic("invalid secret key format")
	}
}
func (tk *Token) SetClaims(claims any) {
	tk.Claims = &NewClaims{
		// Custom claims
		Claims: claims,
		// Default jwt token config
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        xid.New().String(),
			Issuer:    "rainbowhatto",
			Subject:   "rainbowtoken",
			Audience:  []string{"human"},
			ExpiresAt: tk.GetExpiresAt(),
			NotBefore: tk.GetExpiresAt(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
}

// Get
func (tk *Token) GetExpiresAt() *jwt.NumericDate {
	return tk.ExpiresAt
}
func (tk *Token) GetClaims() *NewClaims {
	return tk.Claims
}
func (tk *Token) GetSignAlgorithm() SignAlgorithm {
	return tk.SignAlgorithm
}

// Usecases
func (tk *Token) SignToken() string {
	token := jwt.NewWithClaims(tk.SignAlgorithm, tk.Claims)
	switch tk.SignAlgorithm {
	case HMAC:
		ss, _ := token.SignedString([]byte(tk.Key.GetCommonKey()))
		return ss
	case RSA:
		ss, _ := token.SignedString(tk.Key.GetPrivateKey())
		return ss
	}
	panic("sign token error: token algorithm is invalid")
}
