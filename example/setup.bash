#!/usr/bin/env bash
python -m venv ./venv
source ./venv/bin/activate
pip install --upgrade setuptools wheel pyyaml
pip install ../
