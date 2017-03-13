#! /bin/bash

# shellcheck disable=SC1091
. ./config.sh

start_suite "Test short lived connections between containers, with ebpf proc fallback"

weave_on "$HOST1" launch
# Manually start scope in order to set
#    `WEAVESCOPE_DOCKER_ARGS="-v /dev/net:/sys/kernel/debug/tracing"`
# to make ebpf fail and test the proc fallback.
DOCKER_HOST=tcp://${HOST1}:${DOCKER_PORT} CHECKPOINT_DISABLE=true \
    WEAVESCOPE_DOCKER_ARGS="-v /tmp:/sys/kernel/debug/tracing:ro" \
    "${SCOPE}" launch --probe.ebpf.connections=true
weave_on "$HOST1" run -d --name nginx nginx
weave_on "$HOST1" run -d --name client alpine /bin/sh -c "while true; do \
	wget http://nginx.weave.local:80/ -O - >/dev/null || true; \
	sleep 1; \
done"

wait_for_containers "$HOST1" 60 nginx client

has_container "$HOST1" nginx
has_container "$HOST1" client
has_connection containers "$HOST1" client nginx

scope_end_suite
