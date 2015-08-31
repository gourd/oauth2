// Generated by gourd (version 0.1dev)
// Generated at 2015/08/31 11:12:13 (+0800)
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
	service.Providers.DefineFunc("AuthorizeData", func(r *http.Request) (s service.Service, err error) {
		return GetAuthorizeDataService(r)
	})
}

// GetAuthorizeDataService provides raw AuthorizeDataService
func GetAuthorizeDataService(r *http.Request) (s *AuthorizeDataService, err error) {

	// obtain database
	db, err := upperio.Open(r, "default")
	if err != nil {
		return
	}

	// define service and return
	s = &AuthorizeDataService{db}
	return
}

// AuthorizeDataService serves generic CURD for type AuthorizeData
// Generated by gourd CLI tool
type AuthorizeDataService struct {
	Db db.Database
}

// Create a AuthorizeData in the database, of the parent
func (s *AuthorizeDataService) Create(
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
		log.Printf("Error creating AuthorizeData: %s", err.Error())
		err = service.ErrorInternal
		return
	}

	// apply the key to the entity
	e := ep.(*AuthorizeData)
	e.Id = int32(id.(int64))

	return
}

// Search a AuthorizeData by its condition(s)
func (s *AuthorizeDataService) Search(
	q service.Query, lp service.EntityListPtr) (err error) {

	// get collection
	coll, err := s.Coll()
	if err != nil {
		return
	}

	// retrieve all users
	var res db.Result
	res = coll.Find(upperio.Conds(q.GetConds()))

	// handle paging
	if q.GetOffset() != 0 {
		res = res.Skip(uint(q.GetOffset()))
	}
	if q.GetLimit() != 0 {
		res = res.Limit(uint(q.GetLimit()))
	}

	// get all results
	// TODO: consider to use pipeline pattern
	err = res.All(lp)
	if err != nil {
		err = service.ErrorInternal
	}

	return nil
}

// One returns the first AuthorizeData matches condition(s)
func (s *AuthorizeDataService) One(
	c service.Conds, ep service.EntityPtr) (err error) {

	// retrieve from database
	l := &[]AuthorizeData{}
	q := service.NewQuery().SetConds(c)
	err = s.Search(q, l)
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
	(*ep.(*AuthorizeData)) = (*l)[0]
	return nil
}

// Update AuthorizeData on condition(s)
func (s *AuthorizeDataService) Update(
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
		log.Printf("Error updating AuthorizeData: %s", err.Error())
		err = service.ErrorInternal
	}
	return
}

// Delete AuthorizeData on condition(s)
func (s *AuthorizeDataService) Delete(
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
		log.Printf("Error deleting AuthorizeData: %s", err.Error())
		err = service.ErrorInternal
	}
	return nil
}

// AllocEntity allocate memory for an entity
func (s *AuthorizeDataService) AllocEntity() service.EntityPtr {
	return &AuthorizeData{}
}

// AllocEntityList allocate memory for an entity list
func (s *AuthorizeDataService) AllocEntityList() service.EntityListPtr {
	return &[]AuthorizeData{}
}

// Len inspect the length of an entity list
func (s *AuthorizeDataService) Len(pl service.EntityListPtr) int64 {
	el := pl.(*[]AuthorizeData)
	return int64(len(*el))
}

// Coll return the raw upper.io collection
func (s *AuthorizeDataService) Coll() (coll db.Collection, err error) {
	// get raw collection
	coll, err = s.Db.Collection("oauth2_auth")
	if err != nil {
		log.Printf("Error connecting collection oauth2_auth: %s",
			err.Error())
		err = service.ErrorInternal
	}
	return
}

// Close the database session that AuthorizeData is using
func (s *AuthorizeDataService) Close() error {
	return s.Db.Close()
}
