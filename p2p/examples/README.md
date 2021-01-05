# Run multi party demo

## Multi party keygen

CONFIGFILE is the config json file. You can found the default file here: "p2p/examples/config.json".
```
$ cargo run --example multi_party_keygen_demo CONFIGFILE
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