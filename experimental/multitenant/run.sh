#!/bin/bash

set -eux

eval $(weave env)

start_container() {
    local replicas=$1
    local image=$2
    local basename=$3
    shift 3
    local hostname=${basename}.weave.local

    for i in $(seq ${replicas}); do
        if docker inspect ${basename}${i} >/dev/null 2>&1; then
            docker rm -f ${basename}${i}
        fi
        docker run -d --name=${basename}${i} --hostname=${hostname} $@ ${image}
    done
}

start_container 1 deangiberson/aws-dynamodb-local dynamodb
start_container 1 pakohan/elasticmq sqs
start_container 1 weaveworks/scope-collection collection
start_container 1 weaveworks/scope-query query
start_container 1 weaveworks/scope-control control
start_container 1 weaveworks/scope-static static
start_container 1 weaveworks/scope-frontend frontend --add-host=dns.weave.local:$(weave docker-bridge-ip) --publish=4040:80

