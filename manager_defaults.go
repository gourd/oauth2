package oauth2

import (
	"github.com/RangelReale/osin"
	"github.com/asaskevich/govalidator"
	"github.com/gourd/service"

	"errors"
	"log"
	"net/http"
	"net/url"
	"text/template"
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
<head>
<title>Login</title>
<style>
body, html { margin: 0; font-size: 18pt; background-color: #EEE; }
#login-box { max-width: 100%; width: 300px; margin: 10% auto 0; box-shadow: 0 0 3px #777; background-color: #F9F9F9; }
#login-box h1 { font-size: 1.2em; margin: 0 0 0.5em; }
#login-box .content { margin: 0 20px; padding: 30px 0; text-align: center; }
#login-box .field { display: block; width: 88%; background-color: #FFF; }
#login-box .field { border: solid 1px #EEE; padding: 0.4em 1em; line-height: 1.3em; }
#login-box .actions { text-align: center; }
#login-box button { width: 100%; }
</style>
</head>
<body>
	<div id="login-box"><div class="content">
		<h1>{{ .Title }}</h1>
		<form action="{{ .FormAction }}" method="POST">
			<div class="field-wrapper">
				<input name="user_id" type="text" class="field"
					placeholder="{{ .TextUserId }}" autofocus />
			</div>
			<div class="field-wrapper">
				<input name="password" type="password" class="field"
					placeholder="{{ .TextPassword }}" />
			</div>
			<div class="actions">
				<button type="submit">{{ .TextSubmit }}</button>
			</div>
		</form>
	</div></div>
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

func NewLoginFormFunc(tpl string) LoginFormFunc {

	// compile template for login form
	loginTpl, err := template.New("loginForm").Parse(tpl)
	if err != nil {
		panic(err) // should not happen, simply panic
	}

	return func(w http.ResponseWriter, r *http.Request, aurl *url.URL) (err error) {

		// template variables
		vars := map[string]interface{}{
			"Title":        "Login",
			"FormAction":   aurl,
			"TextUserId":   "Login ID",
			"TextPassword": "Password",
			"TextSubmit":   "Login",
		}

		// render the form with vars
		err = loginTpl.Execute(w, vars)
		if err != nil {
			log.Printf("error executing login template: %#v", err.Error())
			return
		}

		return
	}
}
