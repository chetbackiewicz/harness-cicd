package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// VULN: hardcoded application secret. Should be loaded from a secret manager.
const JWTSecret = "super-secret-key-do-not-share-123"

// VULN: MD5 with no salt is unsuitable for password storage (use bcrypt/argon2).
func weakHash(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func issueToken(username, role string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  username,
		"role": role,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(JWTSecret))
}

// VULN: parseToken does NOT verify the signing method.
// An attacker can submit a token signed with alg=none or alg=HS256/RS256 confusion.
// CVE-2020-26160 also affects this version of jwt-go's audience checking.
func parseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
