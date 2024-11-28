package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/gklps/wallet-frontend/docs" // Local Swagger docs import
	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"            // SQLite driver
	swaggerFiles "github.com/swaggo/files"     // Swagger files
	ginSwagger "github.com/swaggo/gin-swagger" // Swagger UI handler
	"golang.org/x/crypto/bcrypt"               // bcrypt for hashing passwords
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

func main() {
	var err error
	// Initialize SQLite3 database
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create users table if not exists
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT,
    password TEXT,
    name TEXT,
    did TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.Use(cors.Default())
	r.POST("/login", loginHandler)
	r.POST("/create", createUserHandler)
	r.GET("/profile", authenticate, profileHandler)
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
	row := db.QueryRow("SELECT id, email, name, password, did FROM users WHERE email = ?", creds.Email)
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
	var didResponse struct {
		DID string `json:"did"`
	}

	// Create the wallet and fetch the DID
	walletRequest := `{"port": "20000"}`
	resp, err := http.Post("http://localhost:8081/create_wallet", "application/json", bytes.NewBuffer([]byte(walletRequest)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create wallet"})
		return
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&didResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not decode wallet response"})
		return
	}

	// Insert new user into the database with DID
	_, err = db.Exec("INSERT INTO users (email, password, name, did) VALUES (?, ?, ?, ?)", newUser.Email, string(hashedPassword), newUser.Name, didResponse.DID)
	if err != nil {
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
	row := db.QueryRow("SELECT id, email, name, did FROM users WHERE did = ?", did)
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
	row := db.QueryRow("SELECT id, email, name, did FROM users WHERE did = ?", did)
	err := row.Scan(&user.ID, &user.Email, &user.Name, &user.DID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user"})
		return
	}

	c.JSON(http.StatusOK, user)
}
