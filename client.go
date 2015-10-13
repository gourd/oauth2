//go:generate gourd gen service -type=Client -coll=oauth2_client $GOFILE
package oauth2

// Client implements the osin Client interface
type Client struct {
	Id          string      `db:"id,omitempty"`
	Secret      string      `db:"secret"`
	RedirectUri string      `db:"redirect_uri"`
	UserId      string      `db:"user_id"`
	UserData    interface{} `db:"-"`
}

func (c *Client) GetId() string {
	if c == nil {
		return ""
	}
	return c.Id
}

func (c *Client) GetSecret() string {
	if c == nil {
		return ""
	}
	return c.Secret
}

func (c *Client) GetRedirectUri() string {
	if c == nil {
		return ""
	}
	return c.RedirectUri
}

func (c *Client) GetUserData() interface{} {
	if c == nil {
		return nil
	}
	return c.UserData
}
