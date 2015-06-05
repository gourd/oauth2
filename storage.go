package oauth2

import (
	"github.com/RangelReale/osin"
	"github.com/gourd/service"
	"log"
	"net/http"
)

// Storage implements osin.Storage
type Storage struct {
	r             *http.Request
	ClientService service.ProviderFunc
	AuthService   service.ProviderFunc
	AccessService service.ProviderFunc
	UserService   service.ProviderFunc
}

// SetRequest set the ClientService
func (store *Storage) SetRequest(r *http.Request) *Storage {
	store.r = r
	return store
}

// UseClientFrom set the ClientService
func (store *Storage) UseClientFrom(p service.ProviderFunc) *Storage {
	store.ClientService = p
	return store
}

// UseAuthFrom set the AuthService
func (store *Storage) UseAuthFrom(p service.ProviderFunc) *Storage {
	store.AuthService = p
	return store
}

// UseAccessFrom set the AccessService
func (store *Storage) UseAccessFrom(p service.ProviderFunc) *Storage {
	store.AccessService = p
	return store
}

// UseUserFrom set the UserService
func (store *Storage) UseUserFrom(p service.ProviderFunc) *Storage {
	store.UserService = p
	return store
}

// Clone the storage
func (store *Storage) Clone() (c osin.Storage) {
	c = &Storage{
		ClientService: store.ClientService,
		AuthService:   store.AuthService,
		AccessService: store.AccessService,
		UserService:   store.UserService,
	}
	return
}

// Close the connection to the storage
func (store *Storage) Close() {
	// placeholder now, will revisit when doing mongodb
}

// GetClient loads the client by id (client_id)
func (store *Storage) GetClient(strId string) (c osin.Client, err error) {

	log.Printf("GetClient %s", strId)

	srv, err := store.ClientService(store.r)
	if err != nil {
		log.Printf("Unable to get client service")
		return
	}

	e := &Client{}
	conds := service.NewConds()
	conds.Add("str_id", strId)

	err = srv.One(conds, e)
	if err != nil {
		log.Printf("%#v", conds)
		log.Printf("Failed running One()")
		return
	} else if e == nil {
		log.Printf("Client not found for the str_id")
		err = service.Errorf(http.StatusNotFound,
			"Client not found for the str_id")
		return
	}

	c = e
	return
}

// SaveAuthorize saves authorize data.
func (store *Storage) SaveAuthorize(d *osin.AuthorizeData) (err error) {

	log.Printf("SaveAuthorize %v", d)

	srv, err := store.AuthService(store.r)
	if err != nil {
		return
	}

	e := &AuthorizeData{}
	err = e.ReadOsin(d)
	if err != nil {
		return
	}

	// store client id with auth in database
	e.ClientId = e.Client.GetId()

	// create the auth data now
	err = srv.Create(service.NewConds(), e)
	return
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (store *Storage) LoadAuthorize(code string) (d *osin.AuthorizeData, err error) {

	log.Printf("LoadAuthorize %s", code)

	// loading osin using osin service
	srv, err := store.AuthService(store.r)
	if err != nil {
		return
	}

	e := &AuthorizeData{}
	conds := service.NewConds()
	conds.Add("code", code)

	err = srv.One(conds, e)
	if err != nil {
		return
	} else if e == nil {
		err = service.Errorf(http.StatusNotFound,
			"AuthorizeData not found for the code")
		return
	}

	// load client here
	var ok bool
	cli, err := store.GetClient(e.ClientId)
	if err != nil {
		return
	} else if e.Client, ok = cli.(*Client); !ok {
		err = service.Errorf(http.StatusInternalServerError,
			"Internal Server Error")
		log.Printf("Unable to cast client into Client type: %#v", cli)
		return
	}

	d = e.ToOsin()
	return
}

// RemoveAuthorize revokes or deletes the authorization code.
func (store *Storage) RemoveAuthorize(code string) (err error) {

	log.Printf("RemoveAuthorize %s", code)

	srv, err := store.AuthService(store.r)
	if err != nil {
		return
	}

	conds := service.NewConds()
	conds.Add("code", code)
	err = srv.Delete(conds)
	return
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (store *Storage) SaveAccess(ad *osin.AccessData) (err error) {

	srv, err := store.AccessService(store.r)
	if err != nil {
		return
	}

	// generate database access type
	e := &AccessData{}
	err = e.ReadOsin(ad)
	if err != nil {
		return
	}

	// store client id with access in database
	e.ClientId = e.Client.GetId()

	// store authorize id with access in database
	if ad.AuthorizeData != nil {
		e.AuthorizeCode = ad.AuthorizeData.Code
	}

	// store previous access id with access in database
	if ad.AccessData != nil {
		e.PrevAccessToken = ad.AccessData.AccessToken
	}

	// create in database
	err = srv.Create(service.NewConds(), e)
	log.Printf("SaveAccess last error: %#v", err)
	return
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (store *Storage) LoadAccess(token string) (d *osin.AccessData, err error) {

	log.Printf("LoadAccess %v", token)

	srv, err := store.AccessService(store.r)
	if err != nil {
		return
	}

	e := &AccessData{}
	conds := service.NewConds()
	conds.Add("access_token", token)

	err = srv.One(conds, e)
	if err != nil {
		return
	} else if e == nil {
		err = service.Errorf(http.StatusNotFound,
			"AccessData not found for the token")
		return
	}

	// load supplementary data
	err = func(e *AccessData) (err error) {

		// load client here
		var ok bool
		cli, err := store.GetClient(e.ClientId)
		if err != nil {
			return
		} else if e.Client, ok = cli.(*Client); !ok {
			err = service.Errorf(http.StatusInternalServerError,
				"Internal Server Error")
			log.Printf("Unable to cast client into Client type: %#v", cli)
			return
		}

		// load authdata here
		if e.AuthorizeCode != "" {
			a, err := store.LoadAuthorize(e.AuthorizeCode)
			if err != nil {
				return err
			}
			ad := &AuthorizeData{}
			if err = ad.ReadOsin(a); err != nil {
				return err
			}
			e.AuthorizeData = ad
		}

		// load previous access here
		if e.PrevAccessToken != "" {
			a, err := store.LoadAccess(e.PrevAccessToken)
			if err != nil {
				return err
			}
			ad := &AccessData{}
			if err = ad.ReadOsin(a); err != nil {
				return err
			}
			e.AccessData = ad
		}

		return
	}(e)

	if err != nil {
		return
	}

	d = e.ToOsin()
	return
}

// RemoveAccess revokes or deletes an AccessData.
func (store *Storage) RemoveAccess(token string) (err error) {

	log.Printf("RemoveAccess %v", token)

	srv, err := store.AccessService(store.r)
	if err != nil {
		return
	}

	conds := service.NewConds()
	conds.Add("access_token", token)
	err = srv.Delete(conds)
	return
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (store *Storage) LoadRefresh(token string) (d *osin.AccessData, err error) {

	log.Printf("LoadRefresh %v", token)

	srv, err := store.AccessService(store.r)
	if err != nil {
		return
	}

	e := &AccessData{}
	conds := service.NewConds()
	conds.Add("refresh_token", token)

	err = srv.One(conds, e)
	if err != nil {
		return
	} else if e == nil {
		err = service.Errorf(http.StatusNotFound,
			"AccessData not found for the refresh token")
		return
	}

	d = e.ToOsin()
	return
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (store *Storage) RemoveRefresh(token string) (err error) {

	log.Printf("RemoveRefresh %v", token)

	srv, err := store.AccessService(store.r)
	if err != nil {
		return
	}

	conds := service.NewConds()
	conds.Add("refresh_token", token)
	err = srv.Delete(conds)
	return
}
