#!/bin/bash
set -x

curdir=$(pwd)
killall two_party_demo multi_party_keygen_demo multi_party_demo multi_party_sign_demo
killall mpc_ecdsa_web
