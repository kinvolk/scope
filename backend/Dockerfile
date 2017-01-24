FROM ubuntu:yakkety
ENV GOPATH /go
ENV PATH /go/bin:/usr/lib/go-1.7/bin:/usr/bin:/bin:/usr/sbin:/sbin
# vim-common is needed for xxd
RUN apt-get update && \
	apt-get install -y libpcap-dev python-requests time file shellcheck golang-1.7 git gcc-arm-linux-gnueabihf vim-common && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN go clean -i net && \
	go install -tags netgo std && \
	go install -race -tags netgo std
RUN go get -tags netgo \
		github.com/fzipp/gocyclo \
		github.com/golang/lint/golint \
		github.com/kisielk/errcheck \
		gopkg.in/mvdan/sh.v1/cmd/shfmt \
		github.com/fatih/hclfmt \
		github.com/mjibson/esc \
		github.com/client9/misspell/cmd/misspell && \
	chmod a+wr --recursive /usr/local/go/pkg && \
	rm -rf /go/pkg/ /go/src/
COPY build.sh /
ENTRYPOINT ["/build.sh"]
