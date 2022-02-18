# Machine Config

CPU：Intel® Core™ i7-10510U CPU @ 1.80GHz × 8

Memory：16G

Disk：512G

# Performance with p2p network

## Two-Party ECDSA 

| Protocols | KeyGen | Sign-Offline  | Sign-Online|
| ------ | ----- | ------|------|
|[DMZ+21]|  1276ms | 384ms |169ms|
|[XAX+21]|  12ms | 1698ms |1.5ms|


## Multi-Party ECDSA


| (t, n)  | KeyGen | Sign-Offline   |Sign-Online|
| ------- | ------ | ------ |------|
| (1,3)   | 371ms  | 1593ms  |6.1ms |
| (2, 4)  | 426ms  | 4318ms  |14ms |
| (3, 5)  | 510ms  | 5065ms  |19ms|


# Local Performance

## Two-Party ECDSA 

|Protocols| KeyGen | Sign-Offline  | Sign-Online|
| ------ | ----- | ------ |------|
|[DMZ+21]| 1260 ms | 357ms | 142ms |
|[XAX+21]| 11 ms | 1797ms | 0.1ms |


## Multi-Party ECDSA

| (t, n) | KeyGen | Sign-Offline  | Sign-Online |
| ------ | ------ | ----- | ------ |
| (1,3)  | 289ms   | 1503ms | 0.8ms |
| (2, 4) | 345ms  | 3590ms | 1.19ms|
| (4, 8) | 494ms  | 6752ms | 2ms |


