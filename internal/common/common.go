package common

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// ResourceCredentialsSecretEndpointKey is the key inside a connection secret for the connection endpoint
	ResourceCredentialsSecretConnectionStringKey = "connectionString"

	// Status type for Role
	CREATE = "Create"
	SYNC   = "Sync"
	FAIL   = "Fail"
	DELETE = "Delete"

	// Status type for Grant
	GRANTDATABASE = "Database"
	GRANTTABLE    = "Table"

	RESOURCENOTFOUND = "ResourceNotFound"
	CONNECTIONFAILED = "ConnectionFailed"
)

// A ResourceReference is a reference to a resource in an arbitrary namespace.
type ResourceReference struct {
	// Name of the resource.
	Name string `json:"name"`

	// Namespace of the resource.
	Namespace string `json:"namespace"`
}

// A SecretKeySelector is a reference to a secret key in an arbitrary namespace.
type SecretKeySelector struct {
	ResourceReference `json:",inline"`

	// The key to select.
	Key string `json:"key"`
}

// md5Hash generates an MD5 hash of "password + username"
func md5Hash(password, username string) string {
	hash := md5.Sum([]byte(password + username))
	return "md5" + hex.EncodeToString(hash[:])
}

// verifyMD5 checks if the given password matches the MD5 hash stored in PostgreSQL
func VerifyMD5(inputPassword, username, storedHash string) bool {
	return md5Hash(inputPassword, username) == storedHash
}

// Function to verify SCRAM-SHA-256 password
func VerifySCRAM(password, scramHash string) bool {
	// Example SCRAM hash format:
	// SCRAM-SHA-256$4096:salt:stored_key:server_key
	parts := strings.Split(scramHash, "$")
	if len(parts) != 3 {
		log.Fatal("Invalid SCRAM format")
	}

	// Extracting iteration count, salt, stored key, and server key
	iterations, err := strconv.Atoi(strings.Split(parts[1], ":")[0])
	if err != nil {
		log.Fatal("Invalid iterations count")
	}

	salt, err := base64.StdEncoding.DecodeString(strings.Split(parts[1], ":")[1])
	if err != nil {
		log.Fatal("Invalid salt encoding")
	}

	storedKeyHash, err := base64.StdEncoding.DecodeString(strings.Split(parts[2], ":")[0])
	if err != nil {
		log.Fatal("Invalid stored key encoding")
	}

	// Step 1: Generate the salted password using PBKDF2
	saltedPassword := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	// Step 2: Compute ClientKey = HMAC(SaltedPassword, "Client Key")
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))

	// Step 3: Compute StoredKey = SHA256(ClientKey)
	storedKey := sha256.Sum256(clientKey)

	// Step 4: Compare computed StoredKey with the one from hash
	return hmac.Equal(storedKey[:], storedKeyHash)
}

// Helper function for HMAC-SHA256
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
