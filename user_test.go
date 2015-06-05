package oauth2

import (
	"math/rand"
	"testing"
)

func dummyNewUser(password string) *User {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	randSeq := func(n int) string {
		b := make([]rune, n)
		for i := range b {
			b[i] = letters[rand.Intn(len(letters))]
		}
		return string(b)
	}

	u := &User{
		Username: randSeq(10),
	}
	u.Password = u.Hash(password)
	return u
}

func TestUser(t *testing.T) {
	var u OAuth2User = &User{}
	_ = u
}
