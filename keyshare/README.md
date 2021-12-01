# Use ECDSA KeyShare
## Compile lib
 ```shell
 cd keyshare
 cargo build --release
 ```
 ## Run test
 ```shell
 cd test
mkdir build && cd build
cmake -DKEYSHARE_DIR=/xxx/CG-MPC-ECDSA/target/release  ..
make
./key_share_test
```
## Generate C header
```shell
cbindgen src/lib.rs -l c > key_share.h
```

