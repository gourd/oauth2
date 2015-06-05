package oauth2

import (
	"strings"
)

// ReadScopes read a string and return scopes list
func ReadScopes(str string) (s *Scopes) {
	s = &Scopes{}
	*s = strings.Split(str, ",")
	return
}

// Scopes represents a list of scope
type Scopes []string

// Has determine if the scopes list contain the searching scope
func (s *Scopes) Has(search string) bool {
	// search the primary search target
	for _, scope := range *s {
		if scope == search {
			return true
		}
	}
	return false
}

// HasAny determine if the scopes list contain any of the given
// scope to search
func (s *Scopes) HasAny(searches ...string) bool {
	// search all the other results
	for _, search := range searches {
		if s.Has(search) {
			return true
		}
	}
	return false
}
