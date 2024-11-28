package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt" // Use the updated JWT package

	_ "github.com/gklps/wallet-frontend/backend/docs"

	_ "github.com/mattn/go-sqlite3"
	"github.com/swaggo/gin-swagger" // Swagger UI package
	// Swagger files
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key")

// User struct for JSON response
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
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

func main() {
	var err error
	// Initialize SQLite3 database
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create users table if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, name TEXT)`)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.POST("/login", loginHandler)
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
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Check if the user exists in the database
	var user User
	row := db.QueryRow("SELECT id, email, name FROM users WHERE email = ? AND password = ?", creds.Email, creds.Password)
	err := row.Scan(&user.ID, &user.Email, &user.Name)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
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

	c.Next()
}

// Profile handler to return user profile information
// @Summary Get user profile by ID
// @Description Fetch user information from the database using the JWT token
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} User
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /profile [get]
func profileHandler(c *gin.Context) {
	// Extract user ID from token claims
	tokenString := c.GetHeader("Authorization")[7:]
	token, _ := jwt.Parse(tokenString, nil)
	claims := token.Claims.(jwt.MapClaims)
	userID := claims["sub"].(float64)

	// Fetch user info from database
	var user User
	row := db.QueryRow("SELECT id, email, name FROM users WHERE id = ?", userID)
	err := row.Scan(&user.ID, &user.Email, &user.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user"})
		return
	}

	c.JSON(http.StatusOK, user)
}
