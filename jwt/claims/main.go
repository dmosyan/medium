package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("secret-key")

// Generates a JWT token with custom claims
func GenerateJWT(role string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  "user123",                               // User identifier
		"role": role,                                    // Custom role claim
		"exp":  time.Now().Add(time.Minute * 10).Unix(), // Token expiration
		"iat":  time.Now().Unix(),                       // Issued at
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// Middleware to protect endpoints based on JWT claims
func jwtMiddleware(next http.HandlerFunc, requiredRole string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract and check claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if role, ok := claims["role"].(string); ok && role == requiredRole {
				next(w, r)
				return
			}
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		http.Error(w, "Invalid claims", http.StatusUnauthorized)
	}
}

func adminEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome, Admin!")
}

func userEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome, User!")
}

func main() {
	// Generate 2 tokens and print them
	adminToken, _ := GenerateJWT("admin")
	userToken, _ := GenerateJWT("user")
	fmt.Println("Admin Token:", adminToken)
	fmt.Println("User Token:", userToken)

	// Create HTTP server
	http.HandleFunc("/admin", jwtMiddleware(adminEndpoint, "admin"))
	http.HandleFunc("/user", jwtMiddleware(userEndpoint, "user"))

	fmt.Println("Server running on http://localhost:3000")
	http.ListenAndServe(":3000", nil)
}
