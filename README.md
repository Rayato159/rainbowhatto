<h1>🌈 Rainbow Hatto</h1>

<strong>Rainbow Hatto is the <strong>authentication</strong> and <strong>authorization</strong> package for Golang.</strong>

<p>The authentication is based on <strong>Jwt (Json Web Token) </strong> and the authentication methodology is <strong>based on role-based access control (RBAC)</strong></p>

<h2>Content</h2>
<ul>
    <li><a href="#intstallation">Installation</a></li>
    <li><a href="#function">Function</a></li>
    <li><a href="#type">Type</a></li>
    <ul>
        <li><a href="#signalgorithm">SignAlgorithm</a></li>
        <li><a href="#claims">Claims</a></li>
    </ul>
    <li><a href="#quickstart">Quickstart</a></li>
    <ul>
        <li><a href="#hmac">HMAC Token</a></li>
        <li><a href="#rsa">RSA token</a></li>
    </ul>
</ul>

<h2 id="intstallation">Installation</h2>

```bash
go get github.com/Rayato159/rainbowhatto
```

<h2 id="function">Function</h2>

```go
func BuildToken(alg src.SignAlgorithm, cfg Config) src.IToken {...}
func ReverseHMACToken(token string, secret string) (*Claims, error) {...}
func ReverseRSAToken(token string, path string) (*Claims, error) {...}
```

<h2 id="type">Type</h2>

<h3 id="signalgorithm">SignAlgorithm</h3>
<p>Just call a below function to get a SignAlgorithm type</p>

```go
func HMAC() src.SignAlgorithm {...} // return HMAC type
func RSA() src.SignAlgorithm {...} // return RSA type
```

<h3 id="claims">Claims</h3>

```go
type Claims struct {
	*src.NewClaims `json:"claims"`
}

type NewClaims struct {
	Claims any `json:"claims"`
	jwt.RegisteredClaims
}
```

Detail of registered claims
```txt
ID:        xid,
Issuer:    "rainbowhatto",
Subject:   "rainbowtoken",
Audience:  ["human"],
ExpiresAt: time exp,
NotBefore: time now,
IssuedAt:  time now,
```

<h2 id="quickstart">Quickstart</h2>

<h3 id="hmac">HMAC token (Symmetric key)</h3>

<p>Sign Token</p>

```go
func main() {
	token := rainbowhatto.BuildToken(
		rainbowhatto.HMAC(),
		rainbowhatto.Config{
			ExpiresAt: 86400,
			Secret:    "super-secret",
			Claims: claims{
				Id:   "abdcefg1234",
				Name: "rainbow",
			},
		}
	)
	fmt.Println(token.SignToken())
}
```

<p>Parse Token</p>

```go
func main() {
    token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbXMiOnsiSWQiOiJhYmRjZWZnMTIzNCIsIk5hbWUiOiJyYWluYm93In0sImlzcyI6InJhaW5ib3doYXR0byIsInN1YiI6InJhaW5ib3d0b2tlbiIsImF1ZCI6WyJodW1hbiJdLCJleHAiOjE2NzY4MjcxMzIsIm5iZiI6MTY3Njc0MDczMiwiaWF0IjoxNjc2NzQwNzMyLCJqdGkiOiJjZm9nZ3Y2bmRyYzBibjRyOGQ4MCJ9.lzBu_zRgtc0oTqkZyjatJu7u8PGeBXALcICdTf7zUcs"
    claims, err := rainbowhatto.ReverseHMACToken(token, "super-secret")
    if err != nil {
        panic(err)
    }
    fmt.Println(claims)
}
```

<h3 id="rsa">RSA token (asymmetric key)</h3>

<p>First Generate a .pem key by the following command as below</p>

```bash
# Gen a private key (the number is just a bytes)
openssl genrsa -out <file_name>.pem 2048

# Get a public key
openssl rsa -in <file_name>.pem -pubout -out public.pem
```

<p>Sign Token</p>

```go
func main() {
	token := rainbowhatto.BuildToken(
		rainbowhatto.RSA(),
		rainbowhatto.Config{
			ExpiresAt: 86400,
			Secret:    "./private.pem", // Private key path
			Claims: claims{
				Id:   "abdcefg1234",
				Name: "rainbow",
			},
		}
	)
	fmt.Println(token.SignToken())
}
```

<p>Parse Token</p>

```go
func main() {
    token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbXMiOnsiSWQiOiJhYmRjZWZnMTIzNCIsIk5hbWUiOiJyYWluYm93In0sImlzcyI6InJhaW5ib3doYXR0byIsInN1YiI6InJhaW5ib3d0b2tlbiIsImF1ZCI6WyJodW1hbiJdLCJleHAiOjE2NzY4MjcxNTIsIm5iZiI6MTY3Njc0MDc1MiwiaWF0IjoxNjc2NzQwNzUyLCJqdGkiOiJjZm9naDQ2bmRyYzRwODc0MHBjZyJ9.NSB3DoBjw4XNkiB8_Cnw29qioVp1Y9nRBj5To-k-_yldx74hquGEvni7ZyHio_eAoPRAbi8EdZNNtLyt0wSl3bLvzgsl4b5fvHnVfcp55i9lyUH0odDHnNXq7fWOcNqH4QaMVF2LcJ66AffjDgiePbR7ob8YyovgMDYjU4x73wkyrzNqAJBugbjgBX9g1wd-aGo9N1i0sYas6YBMRbQAhl4XrtVpZj-YQkHePYYrU6Xt6DiE5vhtAuiDRqD4B9gXOStHV6VtLVnjAFJSFidYAXjV0GKzdaOl84yddNL2ZSwFf6JcD4AJ7AGuIlXmA7EC5yC5pwKjVNcFopVZjUKjyA"
    claims, err := rainbowhatto.ReverseHMACToken(token, "./public.pem") // Public key path
    if err != nil {
        panic(err)
    }
    fmt.Println(claims)
}
```
