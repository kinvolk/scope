#! /bin/bash

# shellcheck disable=SC1091
. ./config.sh

start_suite "Launch scope and check it boots, with ebpf connection tracking enabled"

scope_on "$HOST1" launch --probe.ebpf.connections=true

wait_for_containers "$HOST1" 60 weavescope

has_container "$HOST1" weavescope

endpoints_have_ebpf "$HOST1"

scope_end_suite
