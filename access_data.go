//go:generate gourd gen service -type=AccessData -coll=oauth2_access $GOFILE
package oauth2

import (
	"github.com/RangelReale/osin"
	"time"
)

// AccessData interfacing database to osin storage I/O of same name
type AccessData struct {

	// Authorize Data Id
	Id int32 `db:"id,omitempty"`

	// Client Id the data is linked to
	ClientId string `db:"client_id"`

	// Client information
	Client *Client `db:"-"`

	// Authorize id
	AuthorizeCode string `db:"auth_code"`

	// Authorize data, for authorization code
	AuthorizeData *AuthorizeData `db:"-"`

	// Previous access data id
	PrevAccessToken string `db:"prev_access_token"`

	// Previous access data, for refresh token
	AccessData *AccessData `db:"-"`

	// Access token
	AccessToken string `db:"access_token"`

	// Refresh Token. Can be blank
	RefreshToken string `db:"refresh_token"`

	// Token expiration in seconds
	ExpiresIn int32 `db:"expires_in"`

	// Requested scope
	Scope string `db:"scope"`

	// Redirect Uri from request
	RedirectUri string `db:"redirect_uri"`

	// Date created
	CreatedAt time.Time `db:"created_at"`

	// User Id the data is linked to
	UserId int64 `db:"user_id"`

	// Data to be passed to storage. Not used by the osin library.
	UserData interface{} `db:"-"`
}

// ToOsin returns an osin version of the struct of osin I/O
func (d *AccessData) ToOsin() (od *osin.AccessData) {
	od = &osin.AccessData{}
	od.Client = d.Client
	od.AuthorizeData = d.AuthorizeData.ToOsin()
	od.AccessData = d.AccessData.ToOsin()
	od.AccessToken = d.AccessToken
	od.RefreshToken = d.RefreshToken
	od.ExpiresIn = d.ExpiresIn
	od.Scope = d.Scope
	od.RedirectUri = d.RedirectUri
	od.CreatedAt = d.CreatedAt
	od.UserData = d.UserData
	return
}

func (d *AccessData) ReadOsin(od *osin.AccessData) error {
	return nil
}
