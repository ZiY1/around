package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	elastic "gopkg.in/olivere/elastic.v3"
	"net/http"
	"reflect"
	"regexp"
	"time"
)

const (
	TYPE_USER = "user"
)

var (
	usernamePattern = regexp.MustCompile("^[a-zA-Z0-9]+$").MatchString
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Age      int    `json:"age"`
	Gender   string `json:"gender"`
}

// checkUser checks whether user is valid
func checkUser(username string, password string) bool {
	esClient, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		fmt.Println("ES is not setup %v\n", err)
		return false
	}

	// Search with a term query
	termQuery := elastic.NewTermQuery("username", username)
	queryResult, err := esClient.Search().
		Index(INDEX).
		Query(termQuery).
		Pretty(true).
		Do()
	if err != nil {
		fmt.Println("ES query fail %v\n", err)
		return false
	}

	var tyu User
	for _, item := range queryResult.Each(reflect.TypeOf(tyu)) {
		u := item.(User)
		return u.Username == username && u.Password == password
	}

	// If no user exist, return false.
	return false
}

// Add a new user. Return true if successfully.
func addUser(user User) bool {
	esClient, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		fmt.Println("ES is not setup %v\n", err)
		return false
	}

	termQuery := elastic.NewTermQuery("username", user.Username)
	queryResult, err := esClient.Search().
		Index(INDEX).
		Query(termQuery).
		Pretty(true).
		Do()

	if err != nil {
		fmt.Println("ES query fail %v\n", err)
		return false
	}

	if queryResult.Hits.TotalHits > 0 {
		fmt.Printf("User %s already exists, cannot create duplicate user.\n", user.Username)
		return false
	}

	_, err = esClient.Index().
		Index(INDEX).
		Type(TYPE_USER).
		BodyJson(user).
		Refresh(true).
		Do()

	if err != nil {
		fmt.Println("ES save user failed fail %v\n", err)
		return false
	}

	return true
}

// If signup is successful, a new session is created.
func signupHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one signup request")

	decoder := json.NewDecoder(r.Body)
	var user User
	if err := decoder.Decode(&user); err != nil {
		panic(err)
		return
	}

	if user.Username == "" || user.Password == "" || usernamePattern(user.Username) {
		if addUser(user) {
			fmt.Println("User added successfully")
			w.Write([]byte("User added successfully"))
		} else {
			fmt.Println("Failed to add a new user")
			http.Error(w, "Failed to add a new user", http.StatusInternalServerError)
		}
	} else {
		fmt.Println("Empty password or username or invalid username")
		http.Error(w, "Empty password or username or invalid username", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// If login is successful, a new token is created.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one login request")

	decoder := json.NewDecoder(r.Body)
	var user User
	if err := decoder.Decode(&user); err != nil {
		panic(err)
	}

	if checkUser(user.Username, user.Password) {
		token := jwt.New(jwt.SigningMethodHS256)
		// Set token claims
		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

		// Sign the token with our secret
		tokenString, _ := token.SignedString(mySigningKey)

		// Finally, write the token to the browser window
		w.Write([]byte(tokenString))
	} else {
		fmt.Println("Invalid password or username.")
		http.Error(w, "Invalid password or username", http.StatusForbidden)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}
