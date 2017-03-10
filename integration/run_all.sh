#!/bin/bash

set -e

for i in $(seq 11 99) ; do
  cp 300_internet_edge_test.sh 3${i}_internet_edge_test.sh
done

# shellcheck disable=SC1091
. ./config.sh

../tools/integration/run_all.sh "$@"
