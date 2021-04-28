#!/bin/bash

build_type=${1:-"release"} # debug or release
cargo build --examples --${build_type}
