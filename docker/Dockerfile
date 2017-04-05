FROM weaveworks/cloud-agent
WORKDIR /home/weave
RUN apk add --update runit tshark && \
	rm -rf /var/cache/apk/*
ADD ./docker.tgz /
COPY ./weave /usr/bin/
COPY ./raw-pipe-trigger /usr/bin
COPY ./scope ./runsvinit ./entrypoint.sh /home/weave/
COPY ./run-app /etc/service/app/run
COPY ./run-probe /etc/service/probe/run
EXPOSE 4040
ENTRYPOINT ["/home/weave/entrypoint.sh"]
