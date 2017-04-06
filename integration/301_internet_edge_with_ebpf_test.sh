#! /bin/bash

# shellcheck disable=SC1091
. ./config.sh

start_suite "Test short lived connections from the Internet"

weave_on "$HOST1" launch
scope_on "$HOST1" launch --probe.ebpf.connections=true

#for i in $(seq 1 20) ; do
#    ps aux | grep '[i]ptables' || true
#    cat /proc/net/unix | grep 'xtables' || true
#done

set -x

docker_on "$HOST1" logs weavescope 2>&1

docker_on "$HOST1" run -d -p 80:80 --name nginx nginx

do_connections() {
    while true; do
        curl -s "http://$HOST1:80/" >/dev/null || true
        sleep 1
    done
}
do_connections &

wait_for_containers "$HOST1" 60 nginx "The Internet"

has_connection_by_id containers "$HOST1" "in-theinternet" "$(node_id containers "$HOST1" nginx)"

endpoints_have_ebpf "$HOST1"

kill %do_connections

scope_end_suite
