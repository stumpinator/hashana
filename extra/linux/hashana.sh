#!/bin/bash
export HASHANA_HOME=${HASHANA_HOME:-/hashana}
export HASHANA_PORT=${HASHANA_PORT:-5557}
export HASHANA_PYTHON=${HASHANA_PYTHON:-python}

"${HASHANA_PYTHON}" "${HASHANA_HOME}/zmq_server.py"
