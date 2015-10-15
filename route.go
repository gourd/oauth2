package oauth2

import (
	"github.com/gorilla/pat"

	"log"
)

// RoutePat adds manager's endpoint to a pat router
func RoutePat(rtr *pat.Router, base string, ep *Endpoints) {

	// tell user where the endpoints are
	log.Printf("OAuth2 endpoints"+
		"\nauthorize endpoint: %s/authorize"+
		"\ntoken endpoint:     %s/token",
		base, base)

	// bind handler with pat
	rtr.Get(base+"/authorize", ep.Auth)
	rtr.Post(base+"/authorize", ep.Auth)
	rtr.Get(base+"/token", ep.Token)
	rtr.Post(base+"/token", ep.Token)
	rtr.Get(base+"/info", ep.Info)

}
