// Generated by gourd (version 0.1dev)
// Generated at 2015/08/14 22:52:43 (+0800)
// Note: If you want to re-generate this file in the future,
//       do not change it.

package oauth2

import (
	"github.com/gourd/service"
	"github.com/gourd/service/upperio"
	"net/http"

	"log"
	"upper.io/db"
)

func init() {
	// define service provider with proxy
	service.Providers.DefineFunc("Client", func(r *http.Request) (s service.Service, err error) {
		return GetClientService(r)
	})
}

// GetClientService provides raw ClientService
func GetClientService(r *http.Request) (s *ClientService, err error) {

	// obtain database
	db, err := upperio.Open(r, "default")
	if err != nil {
		return
	}

	// define service and return
	s = &ClientService{db}
	return
}

// ClientService serves generic CURD for type Client
// Generated by gourd CLI tool
type ClientService struct {
	Db db.Database
}

// Close the database session
func (s *ClientService) Close() error {
	return s.Db.Close()
}

// Create a Client in the database, of the parent
func (s *ClientService) Create(
	cond service.Conds, ep service.EntityPtr) (err error) {

	// get collection
	coll, err := s.Coll()
	if err != nil {
		return
	}

	// apply random uuid string to string id

	//TODO: convert cond into parentkey and
	//      enforce to the entity

	// add the entity to collection

	id, err := coll.Append(ep)

	if err != nil {
		log.Printf("Error creating Client: %s", err.Error())
		err = service.ErrorInternal
		return
	}

	// apply the key to the entity
	e := ep.(*Client)
	e.Id = int64(id.(int64))

	return
}

// Search a Client by its condition(s)
func (s *ClientService) Search(
	c service.Conds, lp service.EntityListPtr) (err error) {

	// get collection
	coll, err := s.Coll()
	if err != nil {
		return
	}

	// get list condition and ignore the error
	cond, _ := c.GetMap()

	// retrieve all users
	var res db.Result
	if len(cond) == 0 {
		res = coll.Find()
	} else {
		res = coll.Find(db.Cond(cond))
	}

	// handle paging
	if c.GetOffset() != 0 {
		res = res.Skip(uint(c.GetOffset()))
	}
	if c.GetLimit() != 0 {
		res = res.Limit(uint(c.GetLimit()))
	}

	// TODO: also work with c.Cond for ListCond (limit and offset)
	err = res.All(lp)
	if err != nil {
		err = service.ErrorInternal
	}

	return nil
}

// One returns the first Client matches condition(s)
func (s *ClientService) One(
	c service.Conds, ep service.EntityPtr) (err error) {

	// retrieve from database
	l := &[]Client{}
	err = s.Search(c, l)
	if err != nil {
		return
	}

	// if not found, report
	if len(*l) == 0 {
		err = service.ErrorNotFound
		return
	}

	// assign the value of given point
	// to the first retrieved value
	(*ep.(*Client)) = (*l)[0]
	return nil
}

// Update Client on condition(s)
func (s *ClientService) Update(
	c service.Conds, ep service.EntityPtr) (err error) {

	// get collection
	coll, err := s.Coll()
	if err != nil {
		return
	}

	// get by condition and ignore the error
	cond, _ := c.GetMap()
	res := coll.Find(db.Cond(cond))

	// update the matched entities
	err = res.Update(ep)
	if err != nil {
		log.Printf("Error updating Client: %s", err.Error())
		err = service.ErrorInternal
	}
	return
}

// Delete Client on condition(s)
func (s *ClientService) Delete(
	c service.Conds) (err error) {

	// get collection
	coll, err := s.Coll()
	if err != nil {
		return
	}

	// get by condition and ignore the error
	cond, _ := c.GetMap()
	res := coll.Find(db.Cond(cond))

	// remove the matched entities
	err = res.Remove()
	if err != nil {
		log.Printf("Error deleting Client: %s", err.Error())
		err = service.ErrorInternal
	}
	return nil
}

// AllocEntity allocate memory for an entity
func (s *ClientService) AllocEntity() service.EntityPtr {
	return &Client{}
}

// AllocEntityList allocate memory for an entity list
func (s *ClientService) AllocEntityList() service.EntityListPtr {
	return &[]Client{}
}

// Len inspect the length of an entity list
func (s *ClientService) Len(pl service.EntityListPtr) int64 {
	el := pl.(*[]Client)
	return int64(len(*el))
}

// Coll return the raw upper.io collection
func (s *ClientService) Coll() (coll db.Collection, err error) {
	// get raw collection
	coll, err = s.Db.Collection("oauth2_client")
	if err != nil {
		log.Printf("Error connecting collection oauth2_client: %s",
			err.Error())
		err = service.ErrorInternal
	}
	return
}
