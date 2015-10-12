package oauth2

import (
	"encoding/json"
	"fmt"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/pat"
	"github.com/gourd/service"
	"github.com/gourd/service/upperio"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"upper.io/db/sqlite"
)

// example server web app
func testOAuth2ServerApp() http.Handler {

	// define test db
	upperio.Define("default", sqlite.Adapter, sqlite.ConnectionURL{
		Database: `./_test/sqlite3.db`,
	})

	rtr := pat.New()

	// oauth2 manager
	m := NewManager()

	// add oauth2 endpoints to router
	// ServeEndpoints bind OAuth2 endpoints to a given base path
	// Note: this is router specific and need to be generated somehow
	RoutePat(rtr, "/oauth", m.GetEndpoints())

	// add a route the requires access
	rtr.Get("/content", func(w http.ResponseWriter, r *http.Request) {

		log.Printf("Dummy content page accessed")

		// obtain access
		a, err := GetAccess(r)
		if err != nil {
			log.Printf("Dummy content: access error: %s", err.Error())
			fmt.Fprint(w, "Permission Denied")
			return
		}

		// test the access
		if a == nil {
			fmt.Fprint(w, "Unable to gain Access")
			return
		}

		// no news is good news
		fmt.Fprint(w, "Success")
	})

	// create negroni middleware handler
	// with middlewares
	n := negroni.New()
	n.Use(negroni.Wrap(m.Middleware()))

	// use router in negroni
	n.UseHandler(rtr)

	return n
}

// example client web app in the login
func testOAuth2ClientApp(path string) http.Handler {
	rtr := pat.New()

	// add dummy client reception of redirection
	rtr.Get(path, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		enc := json.NewEncoder(w)
		enc.Encode(map[string]string{
			"code":  r.Form.Get("code"),
			"token": r.Form.Get("token"),
		})
	})

	return rtr
}

func TestOAuth2(t *testing.T) {

	// create test oauth2 server
	ts := httptest.NewServer(testOAuth2ServerApp())
	defer ts.Close()

	// create test client server
	tcsbase := "/example_app/"
	tcspath := tcsbase + "code"
	tcs := httptest.NewServer(testOAuth2ClientApp(tcspath))
	defer tcs.Close()

	// a dummy password for dummy user
	password := "password"

	// create dummy oauth client and user
	c, u := func(tcs *httptest.Server, password, redirect string) (*Client, *User) {
		r := &http.Request{}

		// generate dummy user
		us, err := service.Providers.Service(r, "User")
		if err != nil {
			panic(err)
		}
		u := dummyNewUser(password)
		err = us.Create(service.NewConds(), u)
		if err != nil {
			panic(err)
		}

		// get related dummy client
		cs, err := service.Providers.Service(r, "Client")
		if err != nil {
			panic(err)
		}
		c := dummyNewClient(redirect)
		c.UserId = u.Id
		err = cs.Create(service.NewConds(), c)
		if err != nil {
			panic(err)
		}

		return c, u
	}(tcs, password, tcs.URL+tcsbase)

	// build user request to authorization endpoint
	// get response from client web app redirect uri
	code, err := func(c *Client, u *User, password, redirect string) (code string, err error) {

		log.Printf("Test retrieving code ====")

		// login form
		form := url.Values{}
		form.Add("user_id", u.Username)
		form.Add("password", password)
		log.Printf("form send: %s", form.Encode())

		// build the query string
		q := &url.Values{}
		q.Add("response_type", "code")
		q.Add("client_id", c.GetId())
		q.Add("redirect_uri", redirect)

		req, err := http.NewRequest("POST",
			ts.URL+"/oauth/authorize"+"?"+q.Encode(),
			strings.NewReader(form.Encode()))
		if err != nil {
			err = fmt.Errorf("Failed to form new request: %s", err.Error())
			return
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		// new http client to emulate user request
		hc := &http.Client{}
		resp, err := hc.Do(req)
		if err != nil {
			err = fmt.Errorf("Failed run the request: %s", err.Error())
		}

		log.Printf("Response.Request: %#v", resp.Request.URL)

		// request should be redirected to client app with code
		// the testing client app response with a json containing "code"
		// decode the client app json and retrieve the code
		bodyDecoded := make(map[string]string)
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&bodyDecoded)
		var ok bool
		if code, ok = bodyDecoded["code"]; !ok {
			err = fmt.Errorf("Client app failed to retrieve code in the redirection")
		}
		log.Printf("Response Body: %#v", bodyDecoded["code"])

		return
	}(c, u, password, tcs.URL+tcspath)

	// quite if error
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// retrieve token from token endpoint
	// get response from client web app redirect uri
	token, err := func(c *Client, code, redirect string) (token string, err error) {

		log.Printf("Test retrieving token ====")

		// build user request to token endpoint
		form := &url.Values{}
		form.Add("code", code)
		form.Add("client_id", c.GetId())
		form.Add("client_secret", c.Secret)
		form.Add("grant_type", "authorization_code")
		form.Add("redirect_uri", redirect)
		req, err := http.NewRequest("POST",
			ts.URL+"/oauth/token",
			strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Errorf("Failed to form new request: %s", err.Error())
		}

		// new http client to emulate user request
		hc := &http.Client{}
		resp, err := hc.Do(req)
		if err != nil {
			err = fmt.Errorf("Failed run the request: %s", err.Error())
		}

		// read token from token endpoint response (json)
		bodyDecoded := make(map[string]string)
		dec := json.NewDecoder(resp.Body)
		dec.Decode(&bodyDecoded)

		log.Printf("Response Body: %#v", bodyDecoded)
		var ok bool
		if token, ok = bodyDecoded["access_token"]; !ok {
			err = fmt.Errorf(
				"Unable to parse access_token: %s", err.Error())
		}
		return

	}(c, code, tcs.URL+tcspath)

	// quit if error
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// retrieve a testing content path
	body, err := func(token string) (body string, err error) {

		log.Printf("Test accessing content with token ====")

		req, err := http.NewRequest("GET", ts.URL+"/content", nil)
		req.Header.Add("Authority", token)

		// new http client to emulate user request
		hc := &http.Client{}
		resp, err := hc.Do(req)
		if err != nil {
			err = fmt.Errorf("Failed run the request: %s", err.Error())
			return
		}

		raw, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("Failed to read body: %s", err.Error())
			return
		}

		body = string(raw)
		return
	}(token)

	// quit if error
	if err != nil {
		t.Errorf(err.Error())
		return
	} else if body != "Success" {
		t.Errorf("Content Incorrect. Expecting \"Success\" but get \"%s\"", body)
	}

	// final result
	log.Printf("result: \"%s\"", body)

}
