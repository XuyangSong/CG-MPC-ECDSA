# Run multi party demo

## Multi party keygen

CONFIGFILE is the config json file. You can found the example file here: "p2p/examples/config_3pc.json".
```example
{
    "share_count": 3,
    "threshold": 2,
    "infos": [
        {
            "index": 0,
            "address": "127.0.0.1:64000"
        },
        {
            "index": 1,
            "address": "127.0.0.1:64001"
        },
        {
            "index": 2,
            "address": "127.0.0.1:64002"
        }
    ],
    "message": "xxxxxxxxxxxx",
    "subset": [
        0,
        1,
        2
    ]
}
Specify the party_index, party_index should be less than the total share counts.

```
$ cargo run --example multi_party_keygen_demo <party_index> <CONFIGFILE>
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