package jwtutil

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	AccessTokenSecret  []byte
	RefreshTokenSecret []byte
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	SigningMethod      jwt.SigningMethod
}

type JWTUtil struct {
	cfg Config
}

func NewJWTUtil(cfg Config) *JWTUtil {
	if cfg.SigningMethod == nil {
		cfg.SigningMethod = jwt.SigningMethodHS256
	}
	return &JWTUtil{cfg: cfg}
}

type CustomClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

func (j *JWTUtil) GenerateAccessToken(ctx context.Context, userID string) (string, error) {
	claims := CustomClaims{
		ID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.cfg.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(j.cfg.SigningMethod, claims)
	signedToken, err := token.SignedString(j.cfg.AccessTokenSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return signedToken, nil
}

func (j *JWTUtil) GenerateRefreshToken(ctx context.Context, ID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   ID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.cfg.RefreshTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(j.cfg.SigningMethod, claims)
	signedToken, err := token.SignedString(j.cfg.RefreshTokenSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}
	return signedToken, nil
}

func (j *JWTUtil) ValidateToken(ctx context.Context, tokenStr string, isAccessToken bool) (*CustomClaims, error) {
	var secret []byte
	if isAccessToken {
		secret = j.cfg.AccessTokenSecret
	} else {
		secret = j.cfg.RefreshTokenSecret
	}

	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != j.cfg.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (j *JWTUtil) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	claims, err := j.ValidateToken(ctx, refreshToken, false)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}
	return j.GenerateAccessToken(ctx, claims.ID)
}
