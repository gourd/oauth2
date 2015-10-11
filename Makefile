#
# This Makefile is only for regenerating and testing gourd
# generated components.
#

test: flag.deps
	sqlite3 _test/sqlite3.db < _test/schema.sqlite3.sql
	go test -v

generate: clean
	go generate

flag.deps:
	go get -u github.com/codegangsta/negroni
	go get -u github.com/gourd/service
	go get -u github.com/gourd/service/upperio
	go get -u github.com/gorilla/pat
	go get -u upper.io/db/sqlite
	go get -u github.com/yookoala/restit
	go get -u github.com/satori/go.uuid
	touch flag.deps

clean:
	rm -f *_service.go
	rm -f *_service_rest.go
	rm -f flag.deps

.PHONY: test generate clean
