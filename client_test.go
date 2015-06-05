package oauth2

import (
	"github.com/RangelReale/osin"
	"math/rand"
	"testing"
)

func dummyNewClient(redirectUri string) *Client {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	randSeq := func(n int) string {
		b := make([]rune, n)
		for i := range b {
			b[i] = letters[rand.Intn(len(letters))]
		}
		return string(b)
	}

	return &Client{
		StrId:       randSeq(10),
		Secret:      randSeq(10),
		RedirectUri: redirectUri,
		UserId:      0,
	}
}

func TestClient(t *testing.T) {
	var c osin.Client = &Client{}
	_ = c
}
