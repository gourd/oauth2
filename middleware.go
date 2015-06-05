package oauth2

import (
	"github.com/gorilla/context"
	"github.com/gourd/service"
	"log"
	"net/http"
)

var contextKey int

// Middleware is a generic middleware
// to serve a Storage instance to
type Middleware struct {
	storage *Storage
}

// ServeHTTP implements http.Handler interface method.
// Attach a clone of the storage to context
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Clone storage into context")
	sc := m.storage.Clone()
	s := sc.(*Storage)
	s.SetRequest(r)
	context.Set(r, &contextKey, s)
}

// GetStorageOk returns oauth2 storage in context and a boolean flag.
// If process failed, boolean flag will be false
func GetStorageOk(r *http.Request) (s *Storage, ok bool) {
	raw := context.Get(r, &contextKey)
	s, ok = raw.(*Storage)
	return
}

// GetStorage returns oauth2 storage in context
// or nil if failed
func GetStorage(r *http.Request) *Storage {
	s, _ := GetStorageOk(r)
	return s
}

// GetAccess returns oauth2 AccessData with token
// found in "Authority" header variable
func GetAccess(r *http.Request) (d *AccessData, err error) {
	token := r.Header.Get("Authority")
	return GetTokenAccess(r, token)
}

// GetTokenAccess retrieves oauth2 AccessData of
// provided token
func GetTokenAccess(r *http.Request, token string) (d *AccessData, err error) {

	// retrieve context oauth2 storage
	s, ok := GetStorageOk(r)
	if !ok {
		log.Printf("Failed to retrieve storage from context")
		err = service.ErrorInternal
		return
	}

	// get access by token
	od, err := s.LoadAccess(token)
	if err != nil {
		log.Printf("Token: %s", token)
		log.Printf("Failed to load access: %s", err.Error())
		return
	}
	d = &AccessData{}
	d.ReadOsin(od)
	return
}
