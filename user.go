//go:generate gourd gen service -type=User -coll=user $GOFILE
package oauth2

import (
	"crypto/md5"
	"fmt"
	"io"
	"time"
)

// OAuth2User is the generic user interface
// for OAuth2 login check
type OAuth2User interface {
	// PasswordIs matches a string with the stored password.
	// If the stored password is hash, this function will apply to the
	// input before matching.
	PasswordIs(pass string) bool
}

// User of the API server
type User struct {
	Id       string    `db:"id,omitempty"`
	Username string    `db:"username"`
	Email    string    `db:"email"`
	Password string    `db:"password"`
	Name     string    `db:"name"`
	Created  time.Time `db:"created"`
	Updated  time.Time `db:"updated"`
}

// PasswordIs matches the hash with database stored password
func (u *User) PasswordIs(pass string) bool {
	if u.Password == u.Hash(pass) {
		return true
	}
	return false
}

// Hash provide the standard hashing for password
func (u *User) Hash(password string) string {
	h := md5.New()
	io.WriteString(h, password)
	return fmt.Sprintf("%x", h.Sum(nil))
}
