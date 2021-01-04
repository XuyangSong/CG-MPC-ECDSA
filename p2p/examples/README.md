# Compile multi party demo

```shell
$ cargo build --example multi_party_demo
```

# Run multi party demo

## Multi party keygen

CONFIGFILE is the config json file. You can found the default file here: "p2p/examples/config.json".
```
$ cargo run --example multi_party_demo CONFIGFILE
```

*Please start all nodes before connect.

### KeyGen connect

Connect all keygen peers.
```
>> multikeygenconnect
```

### KeyGen

KeyGen Begin
```
>> keygen
```

### KeyGen Quit

Disconnect peers.
```
>> q
```

## Multi party sgin

CONFIGFILE is the config json file. You can found the default file here: "p2p/examples/config.json".
```
$ cargo run --example multi_party_demo CONFIGPATH
```

*Please start all nodes before connect.

### Sign connect

Connect the subset peers.
```
>> multisignconnect
```

### Sign Begin

```
>> sign
```

### Sign Quit

Disconnect peers.
```
>> q
```







# Performance

## Two party local performance

KeyGen | Sign
-------| -----
877 ms | 368ms


## Multi party local performance
(t, n) | KeyGen | Sign
------ | ------ | ----
(2, 4) | 118ms | 3617ms
(4, 8) | 167ms | 7336ms
(6, 12) | ms | ms
(8, 16) | ms | ms
(12, 24) | ms | ms
(16, 32) | ms | ms