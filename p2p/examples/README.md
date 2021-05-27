# Run multi party demo

## Two party
CONFIGFILE is the config json file. You can found the example file here: "p2p/examples/config_2pc.json".
example
```
{
    "infos": [
        {
            "index": 0,
            "address": "127.0.0.1:64000"
        },
        {
            "index": 1,
            "address": "127.0.0.1:64001"
        }
    ],
    "message": "xxxxxxxxxxxx"
}
```
Specify the party_index 0 or 1.
```
$ cargo run --example two_party_demo <party_index> <CONFIGFILE>
```
*Please start all nodes before connect.

### connect

Connect two parties.
```
>> Connect
```

### KeyGen

KeyGen Begin

* Please run keygen by party 0.
```
>> keygen
```

### KeyGen Quit

Disconnect peers.
```
>> q
```
### sign
* Please run sign by party 0.
```
>> sign
```

### Sign Quit

Disconnect peers.
```
>> q
```

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
```
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
* Please run keygen by party 0.
```
>> keygen
```

### KeyGen Quit

Disconnect peers.
```
>> q
```
## Multi party sign

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
* Please run sign by party 0.

```
>> sign
```

### Sign Quit

Disconnect peers.
```
>> q

```