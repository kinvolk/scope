FROM alpine:edge
ENV GOPATH /go
ENV PATH /go/bin:/usr/lib/go-1.7/bin:/usr/bin:/bin:/usr/sbin:/sbin
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >>/etc/apk/repositories && \
	apk add --update bash runit conntrack-tools iproute2 util-linux curl build-base linux-headers \
	libelf libelf-dev libpcap-dev file git py-requests go && \
	rm -rf /var/cache/apk/*
RUN go clean -i net && \
	go install -tags netgo std
# TODO fix: -race does not work with alpine see https://github.com/golang/go/issues/14481
#	go install -race -tags netgo std
RUN go get -tags netgo \
		github.com/fzipp/gocyclo \
		github.com/golang/lint/golint \
		github.com/kisielk/errcheck \
		github.com/mjibson/esc \
		github.com/client9/misspell/cmd/misspell && \
	rm -rf /go/pkg/ /go/src/

COPY build.sh /
ENTRYPOINT ["/build.sh"]
