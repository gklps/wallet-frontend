package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/gklps/wallet-frontend/docs" // Local Swagger docs import
	"github.com/gklps/wallet-frontend/storage"
	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"            // SQLite driver
	swaggerFiles "github.com/swaggo/files"     // Swagger files
	ginSwagger "github.com/swaggo/gin-swagger" // Swagger UI handler
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/bcrypt" // bcrypt for hashing passwords
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key")

// User struct for JSON response
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	DID   string `json:"did"`
}

// LoginCredentials represents the request body structure for login
type LoginCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse represents the structure of the response containing the JWT token
type TokenResponse struct {
	Token string `json:"token"`
}

// ErrorResponse represents a generic error message
type ErrorResponse struct {
	Error string `json:"error"`
}

// CreateUserRequest represents the structure for creating a new user
type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// did request
type DIDRequest struct {
	Port int `json:"port"`
}

// sign request
type SignRequest struct {
	Data string `json:"data"`
	DID  string `json:"did"`
}

// sign response
type SignResponse struct {
	DID        string `json:"did"`
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

// transaction request
type TxnRequest struct {
	RubixNodePort string  `json:"port"`
	DID           string  `json:"did"`
	ReceiverDID   string  `json:"receiver"`
	RBTAmount     float64 `json:"rbt_amount"`
}

// request to rubix node
type ReqToRubixNode struct {
	RubixNodePort string `json:"port"`
	DID           string `json:"did"`
}

// generate test RBT request
type GenerateTestRBTRequest struct {
	// RubixNodePort string `json:"port"`
	DID        string `json:"did"`
	TokenCount int    `json:"number_of_tokens"`
}

func main() {
	var err error
	// Initialize SQLite3 database
	db, err = storage.InitDatabase()
	if err != nil {
		log.Fatal(err)
	}

	InitJWT(db, []byte("RubixBIPWallet"))

	// Initialize JWT with database and secret
	r := gin.Default()
	// CORS middleware to allow Authorization header
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Requested-With"},
		AllowCredentials: true,
		AllowWildcard:    true,
	}))
	r.POST("/login", loginHandler)
	r.POST("/create", createUserHandler)
	r.GET("/profile", authenticate, profileHandler)

	// API endpoints
	//DID features
	r.POST("/create_wallet", createWalletHandler)
	r.POST("/register_did", registerDIDHandler)
	//RBT features
	r.GET("/request_balance", requestBalanceHandler)
	r.POST("/testrbt/create", createTestRBTHandler)
	//Txn features
	r.POST("/request_txn", requestTransactionHandler)
	r.GET("/txn/by_did", getTxnByDIDHandler)
	r.POST("/sign", signTransactionHandler)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.Run(":8080")
}

// Login handler to authenticate users and issue JWT
// @Summary Login user and get JWT token
// @Description Authenticate user and return a JWT token
// @Tags Auth
// @Accept json
// @Produce json
// @Param credentials body LoginCredentials true "User credentials"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /login [post]
func loginHandler(c *gin.Context) {
	var creds LoginCredentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Retrieve the hashed password and DID from the database for the user
	var storedHashedPassword, did string
	var user User
	row := db.QueryRow("SELECT id, email, name, password, did FROM walletUsers WHERE email = ?", creds.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Name, &storedHashedPassword, &did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Compare the entered password with the stored hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(creds.Password))
	if err != nil {
		// If the password does not match, return an Unauthorized error
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token using DID as the "sub" claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": did, // Using DID instead of user ID
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// CreateUser handler to create a new user and return the user profile
// @Summary Create a new user
// @Description Register a new user and store the details in the database
// @Tags User
// @Accept json
// @Produce json
// @Param user body CreateUserRequest true "New user data"
// @Success 201 {object} User
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /create [post]
func createUserHandler(c *gin.Context) {
	var newUser CreateUserRequest
	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Hash the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// Call the /create_wallet API to get the DID
	walletRequest := `{"port": 20000}`
	resp, err := http.Post("http://localhost:8080/create_wallet", "application/json", bytes.NewBuffer([]byte(walletRequest)))
	if err != nil {
		log.Printf("Error calling /create_wallet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create wallet"})
		return
	}
	defer resp.Body.Close()

	// Read the raw response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read wallet response"})
		return
	}
	log.Printf("Raw response from /create_wallet: %s", string(body))

	// Decode the response
	var didResponse struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(body, &didResponse); err != nil {
		log.Printf("JSON Unmarshal error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not decode wallet response"})
		return
	}

	// Check if DID is empty
	if didResponse.DID == "" {
		log.Printf("Received empty DID from /create_wallet")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Received empty DID from wallet service"})
		return
	}

	// Insert new user into the database with DID
	_, err = db.Exec("INSERT INTO walletUsers (email, password, name, did) VALUES (?, ?, ?, ?)", newUser.Email, string(hashedPassword), newUser.Name, didResponse.DID)
	if err != nil {
		log.Printf("Database insert error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	// Return a response with the created user's data including the DID
	c.JSON(http.StatusCreated, gin.H{
		"email": newUser.Email,
		"name":  newUser.Name,
		"did":   didResponse.DID,
	})
}

// Middleware to authenticate the user via JWT
// @Summary Authenticate using JWT token
// @Description Authenticate requests with JWT token in Authorization header
// @Tags Auth
// @Accept json
// @Produce json
// @Failure 401 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /profile [get]
func authenticate(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is required"})
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	// Now we can access the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did := claims["sub"].(string)

	// Optionally, you can check the DID in the database
	var user User
	row := db.QueryRow("SELECT id, email, name, did FROM walletUsers WHERE did = ?", did)
	err = row.Scan(&user.ID, &user.Email, &user.Name, &user.DID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DID"})
		c.Abort()
		return
	}

	c.Next()
}

// Profile handler to return user profile information
// @Summary Get user profile by DID
// @Description Fetch user information from the database using the JWT token
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} User
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /profile [get]
func profileHandler(c *gin.Context) {
	// Extract the DID from the token
	tokenString := c.GetHeader("Authorization")[7:] // Strip "Bearer "
	token, _ := jwt.Parse(tokenString, nil)
	claims := token.Claims.(jwt.MapClaims)

	// Use string assertion for DID, since it's a string
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Fetch user info from database using DID
	var user User
	row := db.QueryRow("SELECT id, email, name, did FROM walletUsers WHERE did = ?", did)
	err := row.Scan(&user.ID, &user.Email, &user.Name, &user.DID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// Initialize JWT module with database connection and secret
func InitJWT(database *sql.DB, secret []byte) {
	if db == nil {
		log.Println("Database connection in InitJWT is nil")
	} else {
		log.Println("JWT initialized with database connection")
	}

	db = database
	jwtSecret = secret
}

// generate JWT
func GenerateJWT(did string, receiverDID string, amount float64) (string, error) {
	claims := jwt.MapClaims{
		"did":          did,
		"receiver_did": receiverDID,
		"rbt_amount":   amount,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// define token header
	token.Header["alg"] = "HS256"
	token.Header["typ"] = "JWT"

	//get the signed token
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	// Save token to database
	_, err = db.Exec(
		"INSERT INTO jwt_tokens (did, token, issued_at, expires_at) VALUES (?, ?, ?, ?)",
		did, tokenString, claims["iat"], claims["exp"],
	)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Verify JWT token using public key
func VerifyToken(tokenString string, publicKey *ecdsa.PublicKey) (bool, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is ECDSA
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		log.Printf("failed to parse jwt")
		return false, nil, err
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, claims, nil
	}

	return false, nil, fmt.Errorf("invalid token")
}

// Handler: Create a new wallet and request DID from node
func createWalletHandler(c *gin.Context) {
	var req DIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Generate mnemonic and derive key pair
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	privateKey, publicKey := generateKeyPair(mnemonic)

	// Request user DID from Rubix node
	did, pubKeyStr, err := didRequest(publicKey, strconv.Itoa(req.Port))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to request DID"})
		return
	}

	// Verify the returned public key
	pubKeyBytes, _ := hex.DecodeString(pubKeyStr)
	reconstructedPubKey, _ := secp256k1.ParsePubKey(pubKeyBytes)
	if !publicKey.IsEqual(reconstructedPubKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Public key mismatch \n"})
		return
	}

	// Save user to database
	privKeyStr := hex.EncodeToString(privateKey.Serialize())
	err = storage.InsertUser(did, pubKeyStr, privKeyStr, mnemonic, req.Port)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user data" + err.Error()})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Respond with DID
	c.JSON(http.StatusOK, gin.H{"did": did})
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: registerDIDHandler publishes the user's DID in the network
func registerDIDHandler(c *gin.Context) {
	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := registerDIDRequest(req.DID, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))

}

// Handler: Sign transaction
func signTransactionHandler(c *gin.Context) {
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	dataToSign, _ := hex.DecodeString(req.Data)
	signature, err := signData(user.PrivateKey.ToECDSA(), dataToSign)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign data"})
		return
	}

	// Verify signature
	if !verifySignature(user.PublicKey, dataToSign, signature) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Signature verification failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"did":        user.DID,
		"signature":  hex.EncodeToString(signature),
		"signedData": req.Data,
	})
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request transaction
func requestTransactionHandler(c *gin.Context) {
	var req TxnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	jwtToken, err := GenerateJWT(req.DID, req.ReceiverDID, req.RBTAmount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	isValid, claims, err := VerifyToken(jwtToken, user.PublicKey.ToECDSA())
	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	log.Println("Token claims:", claims)
	result := SendAuthRequest(jwtToken, strconv.Itoa(user.Port))

	c.JSON(http.StatusOK, gin.H{
		"did":    req.DID,
		"jwt":    jwtToken,
		"status": result,
	})
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request RBT balance
func requestBalanceHandler(c *gin.Context) {
	did := c.Query("did")

	if did == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	result, err := RequestBalance(did, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	c.JSON(http.StatusOK, result)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request to generate test RBTs
func createTestRBTHandler(c *gin.Context) {
	var req GenerateTestRBTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := GenerateTestRBT(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request to fetch Txns list by DID
func getTxnByDIDHandler(c *gin.Context) {
	did := c.Query("did")

	if did == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did \n"})
		return
	}

	role := c.Query("role")
	startDate := c.Query("StartDate")
	endDate := c.Query("EndDate")

	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	result, err := RequestTxnsByDID(did, role, startDate, endDate, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	c.JSON(http.StatusOK, result)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Generate secp256k1 key pair from mnemonic
func generateKeyPair(mnemonic string) (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := secp256k1.PrivKeyFromBytes(seed[:32])
	publicKey := privateKey.PubKey()
	return privateKey, publicKey
}

// send DID request to rubix node
func didRequest(pubkey *secp256k1.PublicKey, rubixNodePort string) (string, string, error) {
	pubKeyStr := hex.EncodeToString(pubkey.SerializeCompressed())
	data := map[string]interface{}{
		"public_key": pubKeyStr,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/request-did-for-pubkey", rubixNodePort)
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", "", err
	}
	defer resp.Body.Close()
	fmt.Println("Response Status:", resp.Status)
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", "", err
	}

	fmt.Println("Response Body in did request :", string(data2))

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respPubKey := response["public_key"].(string)
	respDID := response["did"].(string)

	return respDID, respPubKey, nil
}

// SendAuthRequest sends a JWT authentication request to the Rubix node
func SendAuthRequest(jwtToken string, rubixNodePort string) string {
	log.Println("sending auth request to rubix node...")
	authURL := fmt.Sprintf("http://localhost:%s/api/send-jwt-from-wallet", rubixNodePort)
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
		return "Failed to create request"
	}

	// Add headers
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
		return "Error sending request"
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
		return "Error reading response"
	}

	fmt.Printf("Response from Rubix Node: %s\n", body)
	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return "Error unmarshaling response"
	}

	result := response["message"].(string)
	return result
}

// Sign data using secp256k1 private key
func signData(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	//use sign function from crypto library
	signature, err := privateKey.(crypto.Signer).Sign(rand.Reader, data, crypto.SHA3_256)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
		return nil, err
	}

	// return signature, signedData
	return signature, nil
}

// verifySignature verifies the signature using the public key.
func verifySignature(publicKey *secp256k1.PublicKey, data []byte, signature []byte) bool {
	pubKey := publicKey.ToECDSA()

	// Verify the signature using ECDSA's VerifyASN1 function.
	isValid := ecdsa.VerifyASN1(pubKey, data, signature)

	return isValid
}

// RequestBalance sends request to Rubix node to provide RBT balance info
func RequestBalance(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-account-info?did=%s", rubixNodePort, did)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// GenerateTestRBT sends request to generate test RBTs for userd
func GenerateTestRBT(data GenerateTestRBTRequest, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/generate-test-token", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("test token generation failed, %s", respMsg)
	}

	return respMsg, nil
}

// RequestTxnsByDID sends request to Rubix node to provide list of all Txns involving the DID
func RequestTxnsByDID(did string, role string, startDate string, endDate string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-by-did?DID=%s&Role=%s&StartDate=%s&EndDate=%s", rubixNodePort, did, role, "", "")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// registerDIDRequestsends request to rubix node to publish the did info in the network
func registerDIDRequest(did string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"did": did,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/register-did", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("test token generation failed, %s", respMsg)
	}

	return respMsg, nil
}
