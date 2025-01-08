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
	"mime/multipart"
	"net/http"
	"os"
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

// create FT request
type CreateFTRequest struct {
	DID        string `json:"did"`
	FTCount    int    `json:"ft_count"`
	FTName     string `json:"ft_name"`
	TokenCount int    `json:"token_count"`
}

// transfer FT request
type TransferFTReq struct {
	Receiver   string `json:"receiver"`
	Sender     string `json:"sender"`
	FTName     string `json:"ft_name"`
	FTCount    int    `json:"ft_count"`
	Comment    string `json:"comment"`
	QuorumType int    `json:"quorum_type"`
	Password   string `json:"password"`
	CreatorDID string `json:"creatorDID"`
}

// peer details struct
type DIDPeerMap struct {
	SelfDID string `json:"self_did"`
	PeerDID string `json:"DID"`
	DIDType int    `json:"DIDType"`
	PeerID  string `json:"PeerID"`
}

// create NFT request
type CreateNFTRequest struct {
	DID          string `json:"did"`
	MetadataPath string `json:"metadata"`
	ArtifactPath string `json:"artifact"`
}

// subscribe NFT request
type SubscribeNFTRequest struct {
	DID string `json:"did"`
	NFT string `json:"nft"`
}

// deploy NFT request
type DeployNFTRequest struct {
	DID        string `json:"did"`
	NFT        string `json:"nft"`
	QuorumType int    `json:"quorum_type"`
}

// execute NFT request
type ExecuteNFTRequest struct {
	DID        string  `json:"owner"`
	NFT        string  `json:"nft"`
	NFTData    string  `json:"nft_data"`
	NFTValue   float64 `json:"nft_value"`
	Receiver   string  `json:"receiver"`
	QuorumType int     `json:"quorum_type"`
	Comment    string  `json:"comment"`
}

// @title Wallet API Documentation
// @version 1.0
// @description API documentation for the Wallet application.
// @contact.name API Support
// @contact.email support@example.com
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

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
	r.POST("/setup_quorum", authenticate, setupQuorumHandler)
	r.POST("/add_peer", addPeerHandler)
	//RBT features
	r.GET("/request_balance", requestBalanceHandler)
	r.POST("/testrbt/create", createTestRBTHandler)
	r.POST("/rbt/unpledge", unpledgeRBTHandler)
	//Txn features
	r.POST("/request_txn", requestTransactionHandler)
	r.GET("/txn/by_did", getTxnByDIDHandler)
	r.POST("/sign", signTransactionHandler)
	//FT features
	r.POST("/create_ft", createFTHandler)
	r.POST("/transfer_ft", transferFTHandler)
	r.GET("/get_all_ft", getAllFTHandler)
	r.GET("/get_ft_chain", getFTChainHandler)
	//NFT features
	r.POST("create_nft", createNFTHandler)
	r.POST("subscribe_nft", subscribeNFTHandler)
	r.POST("deploy_nft", deployNFTHandler)
	r.POST("execute_nft", executeNFTHandler)
	r.GET("get_nft", getNFTHandler)
	r.GET("get_nft_chain", getNFTChainHandler)
	r.GET("get_all_nft", getAllNFTHandler)

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

	// Create the wallet and fetch the DID
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

	// Store the user DID in the context for downstream handlers
	c.Set("userDID", did)
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

// @Summary Create a new key pair
// @Description Generates a key pair and assigns a DID
// @Tags DID
// @Accept json
// @Produce json
// @Param request body DIDRequest true "Port for DID request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /create_wallet [post]
func createWalletHandler(c *gin.Context) {
	var req DIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input, " + err.Error()})
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	// Generate mnemonic and derive key pair
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	privateKey, publicKey := generateKeyPair(mnemonic)

	// Request user DID from Rubix node
	did, pubKeyStr, err := didRequest(publicKey, strconv.Itoa(req.Port))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid request, " + err.Error()})
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	// Verify the returned public key
	pubKeyBytes, _ := hex.DecodeString(pubKeyStr)
	reconstructedPubKey, _ := secp256k1.ParsePubKey(pubKeyBytes)
	if !publicKey.IsEqual(reconstructedPubKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Public key mismatch \n"})
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	// Save user to database
	privKeyStr := hex.EncodeToString(privateKey.Serialize())
	err = storage.InsertUser(did, pubKeyStr, privKeyStr, mnemonic, req.Port)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user data, " + err.Error()})
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	// Respond with DID
	c.JSON(http.StatusOK, gin.H{"did": did})
	// Add a newline to the response body
	c.Writer.Write([]byte("\n"))
}

// @Summary Register DID
// @Description Publishes the user's DID in the network
// @Tags DID
// @Accept json
// @Produce json
// @Param request body ReqToRubixNode true "DID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /register_did [post]
func registerDIDHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := registerDIDRequest(req.DID, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// @Summary Setup Quorum
// @Description sets up the DID to be a quorum and to pledge
// @Tags DID
// @Accept json
// @Produce json
// @Param request body ReqToRubixNode true "DID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /setup_quorum [post]
func setupQuorumHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := setupQuorumRequest(req.DID, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// registerDIDRequestsends request to rubix node to publish the did info in the network
func setupQuorumRequest(did string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"did":           did,
		"priv_password": "mypassword",
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/setup-quorum", rubixNodePort)
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

// @Summary Add peer to a DID quorum
// @Description Adds a new peer to the quorum of a user's DID
// @Tags DID
// @Accept json
// @Produce json
// @Param request body DIDPeerMap true "Peer details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /add_peer [post]
func addPeerHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var req DIDPeerMap
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.SelfDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := addPeerRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// addPeerRequest request to rubix node to publish the did info in the network
func addPeerRequest(data DIDPeerMap, rubixNodePort string) (string, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/add-peer-details", rubixNodePort)
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

// @Summary Sign a transaction
// @Description Signs a transaction for a user
// @Tags Txn
// @Accept json
// @Produce json
// @Param request body SignRequest true "Transaction signing request"
// @Success 200 {object} SignResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /sign [post]
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

// @Summary Request a transaction
// @Description Initiates a transaction between two DIDs
// @Tags Txn
// @Accept json
// @Produce json
// @Param request body TxnRequest true "Transaction details"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /request_txn [post]
func requestTransactionHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var req TxnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	jwtToken, err := GenerateJWT(req.DID, req.ReceiverDID, req.RBTAmount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
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

// @Summary Get RBT balance
// @Description Retrieves the RBT balance for a user
// @Tags RBT
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /request_balance [get]
func requestBalanceHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
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

// @Summary Create test RBT tokens
// @Description Creates test RBT tokens for a user
// @Tags RBT
// @Accept json
// @Produce json
// @Param request body GenerateTestRBTRequest true "Request to generate test RBTs"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /testrbt/create [post]
func createTestRBTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req GenerateTestRBTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := GenerateTestRBT(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// @Summary Get transactions by DID
// @Description Fetches all transactions involving the specified DID
// @Tags Txn
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Param role query string false "Role in the transaction (e.g., sender, receiver)"
// @Param startDate query string false "Start date for filtering transactions"
// @Param endDate query string false "End date for filtering transactions"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /txn/by_did [get]
func getTxnByDIDHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did \n"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	role := c.Query("role")
	startDate := c.Query("StartDate")
	endDate := c.Query("EndDate")

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
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
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

// @Summary Unpledge RBT tokens
// @Description Unpledges RBT tokens for a user
// @Tags RBT
// @Accept json
// @Produce json
// @Param request body ReqToRubixNode true "Request to unpledge RBTs"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /rbt/unpledge [post]
func unpledgeRBTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := unpledgeRBTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// unpledgeRBTRequest sends request to unpledge pledged RBTs
func unpledgeRBTRequest(data ReqToRubixNode, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/run-unpledge", rubixNodePort)
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

// FT Handlers
// @Summary Create fungible tokens
// @Description Creates fungible tokens for a user
// @Tags FT
// @Accept json
// @Produce json
// @Param request body CreateFTRequest true "Fungible token creation details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /create_ft [post]
func createFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req CreateFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := createFTReq(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// createFTReq requests the rubix node to create FTs
func createFTReq(data CreateFTRequest, rubixNodePort string) (string, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	log.Println("port in str:", rubixNodePort)
	url := fmt.Sprintf("http://localhost:%s/api/create-ft", rubixNodePort)
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

// @Summary Transfer fungible tokens
// @Description Transfers fungible tokens from one user to another
// @Tags FT
// @Accept json
// @Produce json
// @Param request body TransferFTReq true "Fungible token transfer details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /transfer_ft [post]
func transferFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req TransferFTReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.Sender != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := transferFTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// transferFTRequest sends request to transfer FTs
func transferFTRequest(data TransferFTReq, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/initiate-ft-transfer", rubixNodePort)
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

// @Summary Get all fungible tokens
// @Description Retrieves all fungible tokens for a user
// @Tags FT
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /get_all_ft [get]
func getAllFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := getAllFTRequest(did, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getAllFTRequest sends request to Rubix node to provide all FTs' info
func getAllFTRequest(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-ft-info-by-did?did=%s", rubixNodePort, did)
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

// @Summary Get fungible token chain
// @Description Retrieves the chain of a specific fungible token
// @Tags FT
// @Accept json
// @Produce json
// @Param tokenID query string true "Token ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /get_ft_chain [get]
func getFTChainHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}
	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	tokenID := c.Query("tokenID")

	if tokenID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: tokenID"})
		return
	}

	resp, err := getFTChainRequest(tokenID, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getFTChainRequest sends request to Rubix node to provide FT chain
func getFTChainRequest(tokenID string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-ft-token-chain?tokenID=%s", rubixNodePort, tokenID)
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

// NFT Handlers

// @Summary Create a non-fungible token
// @Description Creates a new NFT with metadata and artifact
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body CreateNFTRequest true "NFT creation details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /create_nft [post]
func createNFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req CreateNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := createNFTReq(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// createFTReq requests the rubix node to create FTs
func createNFTReq(data CreateNFTRequest, rubixNodePort string) (string, error) {
	// Create a buffer to hold the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add the "did" field
	err := writer.WriteField("did", data.DID)
	if err != nil {
		fmt.Println("Error adding DID field:", err)
		return "", err
	}

	// Add the "metadata" file
	metadataFile, err := os.Open(data.MetadataPath)
	if err != nil {
		fmt.Println("Error opening metadata file:", err)
		return "", err
	}
	defer metadataFile.Close()

	metadataPart, err := writer.CreateFormFile("metadata", data.MetadataPath)
	if err != nil {
		fmt.Println("Error creating metadata form file:", err)
		return "", err
	}

	_, err = io.Copy(metadataPart, metadataFile)
	if err != nil {
		fmt.Println("Error copying metadata file:", err)
		return "", err
	}

	// Add the "artifact" file
	artifactFile, err := os.Open(data.ArtifactPath)
	if err != nil {
		fmt.Println("Error opening artifact file:", err)
		return "", err
	}
	defer artifactFile.Close()

	artifactPart, err := writer.CreateFormFile("artifact", data.ArtifactPath)
	if err != nil {
		fmt.Println("Error creating artifact form file:", err)
		return "", err
	}

	_, err = io.Copy(artifactPart, artifactFile)
	if err != nil {
		fmt.Println("Error copying artifact file:", err)
		return "", err
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		fmt.Println("Error finalizing form data:", err)
		return "", err
	}

	// Prepare the HTTP request
	url := fmt.Sprintf("http://localhost:%s/api/create-nft", rubixNodePort)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

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

// @Summary Subscribe to an NFT
// @Description Subscribes a user to an NFT
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body SubscribeNFTRequest true "NFT subscription details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /subscribe_nft [post]
func subscribeNFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req SubscribeNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := subscribeNFTRequest(req.NFT, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// subscribeNFTRequest sends request to subscribe NFT
func subscribeNFTRequest(nft string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"nft": nft,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/subscribe-nft", rubixNodePort)
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

// @Summary Deploy an NFT
// @Description Deploys an NFT to the blockchain
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body DeployNFTRequest true "NFT deployment details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /deploy_nft [post]
func deployNFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req DeployNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := deployNFTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// deployNFTRequest sends request to deploy NFT
func deployNFTRequest(data DeployNFTRequest, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/deploy-nft", rubixNodePort)
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

// @Summary Execute an NFT
// @Description Executes an NFT transaction
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body ExecuteNFTRequest true "NFT execution details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /execute_nft [post]
func executeNFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	var req ExecuteNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := executeNFTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// executeNFTRequest sends request to execute NFT
func executeNFTRequest(data ExecuteNFTRequest, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/execute-nft", rubixNodePort)
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

// @Summary Get NFT details
// @Description Retrieves details of a specific NFT
// @Tags NFT
// @Accept json
// @Produce json
// @Param nft query string true "NFT ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /get_nft [get]
func getNFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	nft := c.Query("nft")

	if nft == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	resp, err := getNFTRequest(nft, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getNFTRequest sends request to Rubix node to provide NFT info
func getNFTRequest(nft string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/fetch-nft?nft=%s", rubixNodePort, nft)
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

// @Summary Get NFT chain
// @Description Retrieves the chain of a specific NFT
// @Tags NFT
// @Accept json
// @Produce json
// @Param nft query string true "NFT ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /get_nft_chain [get]
func getNFTChainHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	nft := c.Query("nft")

	if nft == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: tokenID"})
		return
	}

	latest := c.Query("latest")

	resp, err := getNFTChainRequest(nft, latest, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getNFTChainRequest sends request to Rubix node to provide NFT chain
func getNFTChainRequest(nft string, latest string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-nft-token-chain-data?nft=%s&latest=%s", rubixNodePort, nft, latest)
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

// @Summary Get all NFTs
// @Description Retrieves all NFTs for a user
// @Tags NFT
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Security BearerAuth
// @Router /get_all_nft [get]
func getAllNFTHandler(c *gin.Context) {
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

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		c.JSON(http.StatusForbidden, gin.H{"error": "DID mismatch"})
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := getAllNFTRequest(did, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getAllNFTRequest sends request to Rubix node to provide all NFTs' info
func getAllNFTRequest(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-nfts-by-did?did=%s", rubixNodePort, did)
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
