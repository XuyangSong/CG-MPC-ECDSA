# CG-MPC-ECDSA
This project aims to implement two-party and multi-party ECDSA protocols based on class group with Rust.
It currently includes schemes described in [DMZ+21] (published in Asiacrypt 2021) and  [XAX+21] (published in CCS 2021). 

- Introduction of the protocols are as follows:

| Protocol | Introduction                                                 |
| -------- | ------------------------------------------------------------ |
| [DMZ+21]   | This paper proposes efficient two-party and multi-party threshold ECDSA protocols from CL encryptions based on class groups. This protocol avoids the low order assumption, which is a strong and non-standard assumption, and reduces the communication cost in keygen. |
| [XAX+21]   | This paper proposes a framework of two-party ECDSA protocols. It seperates the signing part into online and offline phases. The online phase is non-interactive and somehow optimal, and the offline phase only needs a single call of MtA. |

Here are some notes:
- We adopts CL-based MtA in [CCL+19] when implementing [XAX+21].
- We implement the refresh function. This function allows key shares to be refreshed while keeping the whole secret key (then the public key) unchanged.
- Class group used in this project support multithreaded execution.


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

# Performance
Running with Intel® Core™ i7-10510U CPU @ 1.80GHz × 8.
## performance with p2p network

Two-Party ECDSA 

| Protocols | KeyGen | Sign-Offline  | Sign-Online|
| ------ | ----- | ------|------|
|[DMZ+21]|  1276ms | 384ms |169ms|
|[XAX+21]|  12ms | 1698ms |1.5ms|


Multi-Party ECDSA

| (t, n)  | KeyGen | Sign-Offline   |Sign-Online|
| ------- | ------ | ------ |------|
| (1,3)   | 371ms  | 1593ms  |6.1ms |
| (2, 4)  | 426ms  | 4318ms  |14ms |
| (3, 5)  | 510ms  | 5065ms  |19ms|

## Local Performance

Two-Party ECDSA 

|Protocols| KeyGen | Sign-Offline  | Sign-Online|
| ------ | ----- | ------ |------|
|[DMZ+21]| 1260 ms | 357ms | 142ms |
|[XAX+21]| 11 ms | 1797ms | 0.1ms |


Multi-Party ECDSA

| (t, n) | KeyGen | Sign-Offline  | Sign-Online |
| ------ | ------ | ----- | ------ |
| (1,3)  | 289ms   | 1503ms | 0.8ms |
| (2, 4) | 345ms  | 3590ms | 1.2ms|
| (3, 5) | 382ms  | 4681ms | 1.6ms |

# References
[DMZ+21] <https://link.springer.com/chapter/10.1007/978-3-030-92068-5_19>

[XAX+21] <https://dl.acm.org/doi/pdf/10.1145/3460120.3484803>

[CCL+19] <https://eprint.iacr.org/2019/503.pdf>

[CCL+20] <https://eprint.iacr.org/2020/084.pdf>
