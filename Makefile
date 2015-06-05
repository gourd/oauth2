#
# This Makefile is only for regenerating and testing gourd
# generated components.
#

test: pretest
	go test

generate: clean
	go generate

pretest:
	go get github.com/codegangsta/negroni
	go get github.com/gourd/service
	go get github.com/gourd/service/upperio
	go get github.com/gorilla/pat
	go get upper.io/db/sqlite
	go get github.com/yookoala/restit
	sqlite3 _test/sqlite3.db < _test/schema.sqlite3.sql

clean:
	rm -f *_service.go
	rm -f *_service_rest.go

.PHONY: build prebuild test clean
