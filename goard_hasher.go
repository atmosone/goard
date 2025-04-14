package goard

import (
	"context"

	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	cost int
}

func (b *bcryptHasher) Hash(ctx context.Context, password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (b *bcryptHasher) Compare(ctx context.Context, hash, password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false
	}
	return true
}

func NewBcryptHasher(cost int) Hasher {
	return &bcryptHasher{
		cost: cost,
	}
}
