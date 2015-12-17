BUILD_IN_CONTAINER=true

all: .collection.uptodate .query.uptodate .frontend.uptodate .static.uptodate .control.uptodate .pipes.uptodate

.collection.uptodate: collection/collection collection/Dockerfile
	docker build -t weaveworks/scope-collection collection/
	touch $@

.query.uptodate: query/query query/Dockerfile
	docker build -t weaveworks/scope-query query/
	touch $@

.frontend.uptodate: frontend/*
	docker build -t weaveworks/scope-frontend frontend/
	touch $@

.static.uptodate: static/static static/Dockerfile
	docker build -t weaveworks/scope-static static/
	touch $@

.control.uptodate: control/control control/Dockerfile
	docker build -t weaveworks/scope-control control/
	touch $@

.pipes.uptodate: pipes/pipes pipes/Dockerfile
	docker build -t weaveworks/scope-pipes pipes/
	touch $@

control/control: control/*.go
static/static: static/*.go
collection/collection: collection/*.go *.go
query/query: query/*.go *.go
pipes/pipes: pipes/*.go

ifeq ($(BUILD_IN_CONTAINER),true)
static/static collection/collection query/query control/control pipes/pipes:
	docker run -ti --rm \
		-v $(shell pwd)/../../.pkg:/go/pkg \
		-v $(shell pwd)/../../:/go/src/github.com/weaveworks/scope \
		-e GOARCH -e GOOS \
		weaveworks/scope-backend-build -C experimental/multitenant $@
else
static/static collection/collection query/query control/control pipes/pipes:
	go build -i -ldflags "-extldflags \"-static\"" -tags netgo -o $@ ./$(@D)
endif

clean:
	go clean ./..
	rm -f .*.uptodate collection/collection query/query control/control
