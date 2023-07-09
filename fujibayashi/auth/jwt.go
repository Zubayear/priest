package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// JWT secret key
var jwtSecret = []byte("valar morghulis")
var refreshTokenSecret = []byte("drink water")

// JWT expiration time
var jwtExpiration = time.Minute * 15
var refreshTokenExpiration = time.Hour * 24

// GenerateJWT generates a new JWT token with multiple roles
func GenerateJWT(username string, roles []string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"roles":    roles,
		"exp":      time.Now().Add(jwtExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// GenerateRefreshToken generates a new refresh token
func GenerateRefreshToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(refreshTokenExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(refreshTokenSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateJWT validates the given JWT token and returns the claims if valid
func ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// ValidateRefreshToken validates the given JWT token and returns the claims if valid
func ValidateRefreshToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return refreshTokenSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
