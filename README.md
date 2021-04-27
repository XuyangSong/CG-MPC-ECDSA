# CG-MPC-ECDSA
multi-party ECDSA from Class Group

# Deps

```sh
sudo apt install -y bison llvm clang
```

# How to test
cargo test -- --test-threads=1
# How to run example

cargo run --example pkc20

cargo run --example two_party

# How to run web

```sh
./run_web.sh [<parties> [<debug|release>]]
```
