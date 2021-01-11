# 机器配置信息

CPU：16核，Intel(R) Xeon(R) Platinum 8269CY CPU T 3.10GHz

内存：32G

硬盘：SSD 100G

网卡：100M



# 网络性能

## 两方ECDSA性能

### Security bits: 112, discriminant: 1348

| KeyGen | Sign  |
| ------ | ----- |
| 595 ms | 577ms |



### Security bits: 128, discriminant: 1827

| KeyGen | Sign  |
| ------ | ----- |
| 942 ms | 947ms |



## 多方门限ECDSA性能

### Security bits: 112, discriminant: 1348

| (t, n)  | KeyGen | Sign   |
| ------- | ------ | ------ |
| (1,2)   | 265ms  | 1.88s  |
| (2, 4)  | 278ms  | 3.38s  |
| (4, 8)  | 504ms  | 6.35s  |
| (6, 12) | 823ms  | 9.37s  |
| (8, 16) | 1011ms | 12.38s |



### Security bits: 128, discriminant: 1827

| (t, n)  | KeyGen | Sign   |
| ------- | ------ | ------ |
| (1,2)   | 272ms  | 3.03s  |
| (2, 4)  | 383ms  | 5.56s  |
| (4, 8)  | 644ms  | 10.73s |
| (6, 12) | 942ms  | 15.96s |
| (8, 16) | 1270ms | 21.14s |

# 本地性能

本地性能使用与网络性能测试使用机器性能相同，唯一区别是本地通信与分布式网络通信。

## 本地两方ECDSA性能

### Security bits: 112, discriminant: 1348

| KeyGen | Sign  |
| ------ | ----- |
| 409 ms | 434ms |

### Two party local performance(Security bits 128)

| KeyGen | Sign  |
| ------ | ----- |
| 635 ms | 732ms |



## 本地多方门限ECDSA性能

### Security bits: 112, discriminant: 1348

| (t, n) | KeyGen | Sign  |
| ------ | ------ | ----- |
| (1,2)  | 62ms   | 1.17s |
| (2, 4) | 143ms  | 2.43s |
| (4, 8) | 335ms  | 4.94s |



### Security bits: 128, discriminant: 1827

| (t, n) | KeyGen | Sign  |
| ------ | ------ | ----- |
| (1,2)  | 116ms  | 1.96s |
| (2, 4) | 175ms  | 3.93s |
| (4, 8) | 450ms  | 7.63s |



# Class Group exp性能

## 机器配置

Intel(R) Core(TM) i7-9700K @ 3.6GHz

## Security bits: 128, discriminant: 1827


| exp bit size  | time    |
| ------------- | ------- |
| log(s)+40     | 76.5ms  |
| Log(s)+128+80 | 105.9ms |

