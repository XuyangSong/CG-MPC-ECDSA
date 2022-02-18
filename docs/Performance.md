# Machine Config

CPU：Intel® Core™ i7-10510U CPU @ 1.80GHz × 8

Memory：16G

Disk：512G

# Performance with p2p network

## Two-Party ECDSA 

### **protocol in [DMZ+21]** 
Party One

| KeyGen | Sign  |
| ------ | ----- | 
|  1276ms | 533ms |

Party Two

| KeyGen | Sign  | 
| ------ | ----- | 
|  433ms | 309ms |

### **protocol in [XAX+21]** 
Party One

| KeyGen | Sign  |
| ------ | ----- | 
|  12ms | 1796ms |

Party Two

| KeyGen | Sign  | 
| ------ | ----- | 
|  8ms | 1792ms |

## Multi-Party ECDSA


| (t, n)  | KeyGen | Sign   |
| ------- | ------ | ------ |
| (1,3)   | 371ms  | 892ms  |
| (2, 4)  | 426ms  | 3045ms  |
| (3, 5)  | 510ms  | 4641ms  |


# Local Performance

## Two-Party ECDSA 

### **protocol in [DMZ+21]** 

| KeyGen | Sign-Offline  | Sign-Online|
| ------ | ----- | ------ |
| 1260 ms | 357ms | 142ms |

### **protocol in [XAX+21]** 

| KeyGen | Sign-Offline  | Sign-Online |
| ------ | ----- | ------ |
| 11 ms | 1797ms | 0.1ms |



## Multi-Party ECDSA

| (t, n) | KeyGen | Sign-Offline  | Sign-Online |
| ------ | ------ | ----- | ------ |
| (1,3)  | 289ms   | 1503ms | 0.8ms |
| (2, 4) | 345ms  | 3590ms | 1.19ms|
| (4, 8) | 494ms  | 6752ms | 2ms |


