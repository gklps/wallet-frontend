package storage

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// User data structure for wallet management
type User struct {
	DID        string // IPFS hash (simulated)
	PublicKey  *secp256k1.PublicKey
	PrivateKey *secp256k1.PrivateKey
	// ChildPath int
	Mnemonic string
	Port     int
}

// sqlite database: manages tables for user data and jwt tokens
var db *sql.DB

// initiate database
func InitDatabase() (*sql.DB, error) {
	var err error
	db, err = sql.Open("sqlite3", "./wallet.db")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Create tables if they do not exist
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT UNIQUE NOT NULL,
		public_key BLOB NOT NULL,
		private_key BLOB NOT NULL,
		mnemonic TEXT NOT NULL,
		port INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS jwt_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		token TEXT NOT NULL,
		issued_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (did) REFERENCES users(did)
	);

	CREATE TABLE IF NOT EXISTS walletUsers (
    id INTEGER PRIMARY KEY,
    email TEXT,
    password TEXT,
    name TEXT,
    did TEXT
	)


	`)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	return db, nil
}

// insert user data
func InsertUser(did, publicKey, privateKey, mnemonic string, port int) error {
	if db == nil {
		log.Println("Database connection is nil")
	} else {
		log.Println("Database connection initialized successfully")
	}

	query := `INSERT INTO users (did, public_key, private_key, mnemonic, port) VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(query, did, publicKey, privateKey, mnemonic, port)
	return err
}

// fetch user data from user DID
func GetUserByDID(did string) (*User, error) {
	if db == nil {
		log.Println("Database connection is nil")
	} else {
		log.Println("Database connection initialized successfully")
	}

	query := `SELECT public_key, private_key, mnemonic, port FROM users WHERE did = ?`
	row := db.QueryRow(query, did)

	var publicKey, privateKey, mnemonic string
	var port int
	err := row.Scan(&publicKey, &privateKey, &mnemonic, &port)
	if err != nil {
		return nil, err
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Decode private key
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	return &User{
		DID:        did,
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Mnemonic:   mnemonic,
		Port:       port,
	}, nil
}
