package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/jwt"
	"github.com/lib/pq"
	"golang.org/x/crypto/sha3"
	"gopkg.in/gomail.v2"
)

var (
	secret    []byte  = make([]byte, 6)
	signer            = jwt.NewSigner(jwt.HS512, secret, time.Minute)
	verifier          = jwt.NewVerifier(jwt.HS512, secret)
	db_handle *sql.DB = nil
	email     string
	smtp_pass string
)

type DefaultClaims struct {
	Subject string `json:"sub"`
	IP      string `json:"ip"`
}

func getPair(user_id string, ip string) *jwt.TokenPair {
	claims := DefaultClaims{Subject: user_id, IP: ip}
	token_pair, err := signer.NewTokenPair(claims, claims, 10*time.Minute)
	if err != nil {
		return nil
	}
	// Task explicitly mentioned bcrypt, however, it is restricted to 72 bytes of input data. Since tokens are almost twice as long, I went with SHA512.
	// It may be not enough for passwords, because they repeat themselves pretty often, but tokens are always unique, so attempting to precalculate hash
	// is useless for anyone with malicious intent, and storing hashes should be safe.
	sha3_hash := sha3.Sum512(token_pair.RefreshToken[1 : len(token_pair.RefreshToken)-1]) // Removing quotation marks
	_, err = db_handle.Exec("INSERT INTO refresh (guid, token, ip) VALUES ($1, $2, $3)", user_id, pq.Array(sha3_hash), ip)
	if err != nil {
		return nil
	}
	return &token_pair
}

func SendWarningEmail() error {
	mess := gomail.NewMessage()
	mess.SetHeader("From", email)
	mess.SetHeader("To", email)
	mess.SetHeader("Subject", "New login location")
	mess.SetBody("text/html", "We've noticed login from new IP. If that wasn't you, change your password immediately")
	dial := gomail.NewDialer("smtp.gmail.com", 587, email, smtp_pass)
	return dial.DialAndSend(mess)
}

func generateTokens(ctx iris.Context) {
	user_id := ctx.URLParam("GUID")
	ip := ctx.Request().RemoteAddr
	token_pair := getPair(user_id, ip)
	if token_pair == nil {
		ctx.StopWithStatus(iris.StatusInternalServerError)
		return
	}
	ctx.JSON(*token_pair)
}

func refreshTokens(ctx iris.Context) {
	provided_token := []byte(ctx.URLParam("refresh"))
	ip := ctx.Request().RemoteAddr
	user_id := ctx.URLParam("GUID")
	active_tokens, err := db_handle.Query("SELECT id, ip, token FROM refresh WHERE guid=$1", user_id)
	if err != nil {
		ctx.StopWithStatus(iris.StatusInternalServerError)
		return
	}
	defer active_tokens.Close()
	for active_tokens.Next() {
		var (
			id                 int
			refresh_token_hash [64]byte
			ip_token           string
		)
		var hash_holder string
		active_tokens.Scan(&id, &ip_token, &hash_holder)
		// A blunt way to say the least, however, pq.ByteaArray objects to being parsed into an actual array of bytes, as well as integer arrays, at least strings are working as expected
		for i, char := range strings.Split(strings.Trim(hash_holder, "\"{}"), ",") {
			byte_val, _ := strconv.Atoi(char)
			refresh_token_hash[i] = byte(byte_val)
		}
		if refresh_token_hash == sha3.Sum512(provided_token) {
			_, err = verifier.VerifyToken(provided_token, jwt.Expected{Subject: user_id})
			if err != nil {
				ctx.StopWithText(iris.StatusUnauthorized, "Token expired")
				return
			}
			db_handle.Exec("DELETE FROM refresh WHERE id=$1", id) // Does not allow reuse of the same refresh token
			token_pair := getPair(user_id, ip)
			if token_pair == nil {
				ctx.StopWithStatus(iris.StatusInternalServerError)
				return
			}
			if ip != ip_token {
				err = SendWarningEmail()
				if err != nil { // Can't send a warning? Better safe than sorry, no tokens then
					ctx.StopWithStatus(iris.StatusInternalServerError)
					return
				}
			}
			ctx.JSON(*token_pair)
			return
		}
	}
	ctx.StopWithText(iris.StatusUnauthorized, "Bad refresh token")
}

func prepareApp() *iris.Application {
	secrets_file, err := os.Open("secrets.json")
	if err != nil {
		fmt.Println("Can't open secrets.json")
		return nil
	}
	defer secrets_file.Close()
	buff := make([]byte, 128)
	len, _ := secrets_file.Read(buff)
	var secrets_map map[string]string
	json.Unmarshal(buff[:len], &secrets_map)
	conn_str := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=%s", "postgres", secrets_map["db_pass"], "tokens", "disable")
	db_handle, err = sql.Open("postgres", conn_str)
	if err != nil {
		fmt.Println("Cannot connect to database with supplied info")
		return nil
	}
	secret = []byte(secrets_map["hmac"])
	email = secrets_map["email"]
	smtp_pass = secrets_map["smtp_pass"]

	app := iris.New()
	app.Get("/", generateTokens)
	app.Get("/refresh", refreshTokens)
	return app
}

func main() {
	app := prepareApp()
	defer db_handle.Close()
	if app == nil {
		fmt.Println("Couldn't start an application")
		return
	}
	app.Listen(":8080")
}
