# CG-MPC-ECDSA
This project aims to implement multi-party ECDSA in Rust, currently including schemes described in [DMZ+21] and  [XAX+21]. 

Introduction of two schemes:
| Protocol | Introduction                                                 |
| -------- | ------------------------------------------------------------ |
| [DMZ+21]   | This paper proposes efficient two-party and multi-party threshold ECDSA protocols from CL encryptions based on class groups without the low order assumption (used in [CCL20+] which is stronger and non-standard). |
| [XAX+21]   | This paper proposes an two-party ECDSA whose online phase is non-interactive and only contains a single signature verification and offline phase just needs a single call of MtA. |

Notes:
1. We adopts CL-based MtA in [CCL+19] when implementing [XAX+21].
2. For secret keys, we develop key share and key refresh functions. Key share function supports one party share his secret key to any number shares and the secret key can be reconstructed when the number of shares reach threshold value, except that, a share can be restore by other shares when lost, this function is implemented based on feldman vss scheme. Key refresh function allows secret keys to be refreshed by the threshold number of parties, this function can be used when a secret key is lost.
3. Class group used in this project support multithreaded execution.


# Deps

```sh
sudo apt install -y bison llvm clang
```

# How to use
```shell
$ cargo run --bin mpc-ecdsa

USAGE:
    mpc-ecdsa <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    dmz-multi-keygen    
    dmz-multi-sign      
    dmz-party-one       
    dmz-party-two       
    help                Prints this message or the help of the given subcommand(s)
    key-refresh         
    xax-party-one       
    xax-party-two
```
Details in: 
[cli/README.md](cli/README.md)

Instructions for use of keyshare in:
[keyshare/README.md](keyshare/README.md)

# Performance
Running with Intel® Core™ i7-10510U CPU @ 1.80GHz × 8.
## performance with p2p network

protocol in [DMZ+21] 

Party One

| KeyGen | Sign  |
| ------ | ----- | 
|  1276ms | 533ms |

Party Two

| KeyGen | Sign  | 
| ------ | ----- | 
|  433ms | 309ms |

protocol in [XAX+21]

Party One

| KeyGen | Sign  |
| ------ | ----- | 
|  12ms | 1796ms |

Party Two

| KeyGen | Sign  | 
| ------ | ----- | 
|  8ms | 1792ms |

multi-party protocols in [DMZ+21]

| (t, n)  | KeyGen | Sign   |
| ------- | ------ | ------ |
| (1,3)   | 371ms  | 892ms  |
| (2, 4)  | 426ms  | 3045ms  |
| (3, 5)  | 510ms  | 4641ms  |

## Local Performance

protocol in [DMZ+21]

| KeyGen | Sign-Offline  | Sign-Online|
| ------ | ----- | ------ |
| 1260 ms | 357ms | 142ms |

protocols in [XAX+21]

| KeyGen | Sign-Offline  | Sign-Online |
| ------ | ----- | ------ |
| 11 ms | 1797ms | 0.1ms |

multi-party protocols in [DMZ+21]
| (t, n) | KeyGen | Sign-Offline  | Sign-Online |
| ------ | ------ | ----- | ------ |
| (1,3)  | 289ms   | 1503ms | 0.8ms |
| (2, 4) | 345ms  | 3590ms | 1.19ms|
| (4, 8) | 494ms  | 6752ms | 2ms |

# References
[DMZ+21] <https://link.springer.com/chapter/10.1007/978-3-030-92068-5_19>

[XAX+21] <https://dl.acm.org/doi/pdf/10.1145/3460120.3484803>

[CCL+19] <https://eprint.iacr.org/2019/503.pdf>

[CCL+20] <https://eprint.iacr.org/2020/084.pdf>
