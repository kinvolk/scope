#! /bin/bash

# shellcheck disable=SC1091
. ./config.sh

start_suite "Test short lived connections between containers, with ebpf connection tracking enabled"

weave_on "$HOST1" launch

# Launch the server before Scope
weave_on "$HOST1" run -d --name server busybox /bin/sh -c "while true; do \
		date ;
		sleep 1 ;
	done | nc -l -p 8080"

scope_on "$HOST1" launch --probe.ebpf.connections=true
wait_for_containers "$HOST1" 60 server
has_container "$HOST1" server

weave_on "$HOST1" run -d --name client busybox /bin/sh -c "while true; do \
		date ;
		sleep 1 ;
	done | nc server.weave.local 8080"

wait_for_containers "$HOST1" 60 server client

has_container "$HOST1" client

list_containers "$HOST1"
list_connections "$HOST1"

has_connection containers "$HOST1" client server

endpoints_have_ebpf "$HOST1"

scope_end_suite
