package oauth2

import (
	"github.com/RangelReale/osin"
	"github.com/gourd/service"
	"net/http"
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

// DefaultLoginTpl is the HTML template for login form by default
const DefaultLoginTpl = `
<!DOCTYPE html>
<html>
<body>
	LOGIN {{ .SiteName }}<br/>
	<form action="{{ .FormAction }}" method="POST">
		Login: <input type="text" name="login" /><br/>
		Password: <input type="password" name="password" /><br/>
		<input type="submit"/>
	</form>
</body>
</html>
`

// DefaultLoginParser is the default parser of login HTTP request
func DefaultLoginParser(r *http.Request) (idField, id, password string) {
	idField = "username"
	id = r.Form.Get(idField)
	password = r.Form.Get("password")
	return
}
