package oauth2

import (
	"github.com/gorilla/pat"
)

// RoutePat adds manager's endpoint to a pat router
func RoutePat(rtr *pat.Router, base string, ep *Endpoints) {

	// bind handler with pat
	rtr.Get(base+"/authorize", ep.Auth)
	rtr.Post(base+"/authorize", ep.Auth)
	rtr.Get(base+"/token", ep.Token)
	rtr.Post(base+"/token", ep.Token)

}
