package oauth2

import (
	"errors"
	"github.com/RangelReale/osin"
	"github.com/gourd/service"
	"log"
	"net/http"
	"net/url"
	"text/template"
)

// Endpoints contains http handler func of different endpoints
type Endpoints struct {
	Auth  http.HandlerFunc
	Token http.HandlerFunc
}

// NewManager returns a oauth2 manager with default configs
func NewManager() (m *Manager) {

	m = &Manager{}

	// provide services to auth storage
	// NOTE: these are independent to router
	m.UseStorage(DefaultStorage())

	// provide storage to osin server
	// provide osin server to Manager
	m.InitOsin(DefaultOsinConfig())

	// set default template
	m.SetLoginTpl(DefaultLoginTpl)

	// set default login parser
	m.SetUserFunc(NewUserFunc("user_id"))

	return
}

// UserFunc reads the login form request and returns an OAuth2User
// for the reqeust. If there is error obtaining the user, an error
// is returned
type UserFunc func(r *http.Request, us service.Service) (u OAuth2User, err error)

// Manager handles oauth2 related request
// Also provide middleware for other http handler function
// to access scope related information
type Manager struct {
	storage    *Storage
	osinServer *osin.Server
	loginTpl   string
	userFunc   UserFunc
}

// UseOsin set the OsinServer
func (m *Manager) InitOsin(cfg *osin.ServerConfig) *Manager {
	m.osinServer = osin.NewServer(cfg, m.storage)
	return m
}

// Storage provides a osin storage interface
func (m *Manager) UseStorage(s *Storage) *Manager {
	m.storage = s
	return m
}

// GetEndpoints generate endpoints http handers and return
func (m *Manager) GetEndpoints() *Endpoints {

	// compile template for login form
	loginTpl, err := template.New("loginForm").Parse(m.loginTpl)
	if err != nil {
		panic(err)
	}

	// handle login
	handleLogin := func(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) (err error) {

		w.Header().Add("Content-Type", "text/html;charset=utf8")
		log.Printf("handleLogin")

		// parse POST input
		r.ParseForm()
		if r.Method == "POST" {

			var u OAuth2User
			var us service.Service

			// get and check password
			password := r.Form.Get("password")
			if password == "" {
				err = errors.New("empty password")
				return
			}

			// obtain user service
			us, err = m.storage.User.Service(r)
			if err != nil {
				log.Printf("Error obtaining user service: %s", err.Error())
				err = errors.New("Internal Server Error")
				return
			}

			// get user by userFunc
			u, err = m.userFunc(r, us)
			if err != nil {
				log.Printf("Error obtaining user: %s", err.Error())
				err = errors.New("Internal Server Error")
			}

			// if password does not match
			if !u.PasswordIs(password) {
				log.Print("Incorrect password")
				err = errors.New("username or password incorrect")
			} else {
				log.Printf("Login success")
			}

			// return pointer of user object, allow it to be re-cast
			ar.UserData = u
			return
		}

		// no POST input or incorrect login, show form

		// build action query
		aq := url.Values{}
		aq.Add("response_type", string(ar.Type))
		aq.Add("client_id", ar.Client.GetId())
		aq.Add("state", ar.State)
		aq.Add("scope", ar.Scope)
		aq.Add("redirect_uri", ar.RedirectUri)

		// template variables
		vars := map[string]interface{}{
			"SiteName":   "Gourd: Example 2",
			"FormAction": r.URL.Path + "?" + aq.Encode(),
		}

		// render the form with vars
		err = loginTpl.Execute(w, vars)
		if err != nil {
			log.Printf("error executing login template: %#v", err.Error())
		}
		return
	}

	ep := Endpoints{}

	// authorize endpoint
	ep.Auth = func(w http.ResponseWriter, r *http.Request) {

		log.Printf("auth endpoint")

		srvr := m.osinServer
		resp := srvr.NewResponse()
		resp.Storage.(*Storage).SetRequest(r)

		// handle authorize request with osin
		if ar := srvr.HandleAuthorizeRequest(resp, r); ar != nil {
			log.Printf("handle authorize request")
			if err := handleLogin(ar, w, r); err != nil {
				return
			}
			log.Printf("OAuth2 Authorize Request: User obtained: %#v", ar.UserData)
			ar.Authorized = true
			srvr.FinishAuthorizeRequest(resp, r, ar)
		}
		if resp.InternalError != nil {
			log.Printf("Internal Error: %s", resp.InternalError.Error())
		}
		log.Printf("OAuth2 Authorize Response: %#v", resp)
		osin.OutputJSON(resp, w, r)

	}

	// token endpoint
	ep.Token = func(w http.ResponseWriter, r *http.Request) {

		srvr := m.osinServer
		resp := srvr.NewResponse()
		resp.Storage.(*Storage).SetRequest(r)

		if ar := srvr.HandleAccessRequest(resp, r); ar != nil {
			// TODO: handle authorization
			// check if the user has the permission to grant the scope
			log.Printf("Access successful")
			ar.Authorized = true
			srvr.FinishAccessRequest(resp, r, ar)
		} else if resp.InternalError != nil {
			log.Printf("Internal Error: %s", resp.InternalError.Error())
		}
		log.Printf("OAuth2 Token Response: %#v", resp)
		osin.OutputJSON(resp, w, r)

	}

	return &ep

}

// SetLoginTpl sets the login template
func (m *Manager) SetLoginTpl(tpl string) {
	m.loginTpl = tpl
}

// SetLoginParser sets the parser for login request.
// Will be called when endpoint POST request
//
// Manager will then search user with `idField` equals to `id`.
// Then it will check User.HasPassword(`password`)
// (User should implement OAuth2User interface)
// to see if the password is correct
func (m *Manager) SetUserFunc(f UserFunc) {
	m.userFunc = f
}

// Middleware returns *Middleware with the current storage
func (m *Manager) Middleware() *Middleware {
	return &Middleware{
		storage: m.storage,
	}
}
