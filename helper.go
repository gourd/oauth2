package oauth2

import (
	"github.com/RangelReale/osin"
	"github.com/gorilla/pat"
	"github.com/gourd/service"
)

// DefaultStorage returns Storage that attachs to default services
func DefaultStorage() (s *Storage) {
	s = &Storage{}
	s.UseClientFrom(service.Providers.MustGet("Client"))
	s.UseAuthFrom(service.Providers.MustGet("AuthorizeData"))
	s.UseAccessFrom(service.Providers.MustGet("AccessData"))
	s.UseUserFrom(service.Providers.MustGet("User"))
	return
}

// DefaultOsinConfig returns a preset config suitable
// for most generic oauth2 usage
func DefaultOsinConfig() (cfg *osin.ServerConfig) {
	cfg = osin.NewServerConfig()
	cfg.AllowGetAccessRequest = true
	cfg.AllowClientSecretInParams = true
	cfg.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN,
	}
	cfg.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{
		osin.CODE,
		osin.TOKEN,
	}
	return
}

// RoutePat adds manager's endpoint to a pat router
func RoutePat(m *Manager, rtr *pat.Router, base string) {

	// TODO: also implement other endpoints (e.g. permission endpoint, refresh)
	ep := m.GetEndpoints()

	// bind handler with pat
	rtr.Get(base+"/authorize", ep.Auth)
	rtr.Post(base+"/authorize", ep.Auth)
	rtr.Get(base+"/token", ep.Token)
	rtr.Post(base+"/token", ep.Token)

}
