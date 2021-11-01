#!/bin/bash
set -x

curdir=$(pwd)
killall tmulti_party_ecdsa_keygen multi_party_ecdsa_sign two_party_ecdsa_one two_party_ecdsa_two
killall mpc_ecdsa_web
