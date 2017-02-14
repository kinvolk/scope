#!/bin/bash

set -e

# shellcheck disable=SC1091
. ./config.sh

export PROJECT="${PROJECT:-scope-integration-tests}"
export TEMPLATE_NAME="${TEMPLATE_NAME:-scope-integration-tests-template-schu}"
export NUM_HOSTS=5
# shellcheck disable=SC1091
. "../tools/integration/gce.sh" "$@"
