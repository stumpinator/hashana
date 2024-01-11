#!/bin/bash
export HASHANA_HOME='/hashana'
export HASHANA_VENV="${HASHANA_HOME}/venv"
export HASHANA_PORT='5557'
export HASHANA_PY='zmq_server.py'

cd $HASHANA_HOME
source "${HASHANA_VENV}/bin/activate"
python ${HASHANA_PY}