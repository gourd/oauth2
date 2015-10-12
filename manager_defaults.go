package oauth2

import (
	"github.com/RangelReale/osin"
	"github.com/asaskevich/govalidator"
	"github.com/gourd/service"

	"errors"
	"log"
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
		Login: <input type="text" name="user_id" /><br/>
		Password: <input type="password" name="password" /><br/>
		<input type="submit"/>
	</form>
</body>
</html>
`

// DefaultLoginParser is the default parser of login HTTP request
func NewUserFunc(idName string) UserFunc {
	return func(r *http.Request, us service.Service) (ou OAuth2User, err error) {

		var c service.Conds

		id := r.Form.Get(idName)

		if id == "" {
			err = errors.New("empty user identifier")
			return
		}

		// different condition based on the user_id field format
		if govalidator.IsEmail(id) {
			c = service.NewConds().Add("email", id)
		} else {
			c = service.NewConds().Add("username", id)
		}

		// get user from database
		u := us.AllocEntity()
		err = us.One(c, u)
		if err != nil {
			log.Printf("Error searching user \"%s\": %s", id, err.Error())
			err = errors.New("Internal Server Error")
			return
		}

		// if user does not exists
		if u == nil {
			log.Printf("Unknown user \"%s\" attempt to login", id)
			err = errors.New("Username or Password incorrect")
			return
		}

		// cast the user as OAuth2User
		// and do password check
		ou, ok := u.(OAuth2User)
		if !ok {
			log.Printf("User cannot be cast as OAuth2User")
			err = errors.New("Internal server error")
			return
		}

		return
	}
}
