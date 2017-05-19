FROM ubuntu:yakkety
ENV GOPATH /go
ENV GOVERSION 1.7
ENV PATH /go/bin:/usr/lib/go-${GOVERSION}/bin:/usr/bin:/bin:/usr/sbin:/sbin
RUN apt-get update && \
	apt-get install -y libpcap-dev python-requests time file shellcheck golang-${GOVERSION} git gcc-arm-linux-gnueabihf wget unzip && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN go clean -i net && \
	go install -tags netgo std && \
	go install -race -tags netgo std
RUN go get -tags netgo \
		github.com/fzipp/gocyclo \
		github.com/golang/lint/golint \
		github.com/kisielk/errcheck \
		github.com/mvdan/sh/cmd/shfmt \
		github.com/fatih/hclfmt \
		github.com/mjibson/esc \
		github.com/client9/misspell/cmd/misspell \
		gopkg.in/src-d/proteus.v1/... && \
	( go get -tags netgo  github.com/gogo/protobuf/... || true ) && \
	chmod a+wr --recursive /usr/lib/go-${GOVERSION}/pkg && \
	rm -rf /go/pkg/ # Don't delete /go/src/: proteus needs github.com/gogo/protobuf
RUN mkdir /tmp/protoc && cd /tmp/protoc && \
	wget --quiet https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip && \
	unzip protoc*.zip && \
	cp bin/protoc /bin/ && \
	chmod 755 /bin/protoc && \
	rm -rf /tmp/protoc
COPY build.sh /
ENTRYPOINT ["/build.sh"]
