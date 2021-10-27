# Run ECDSA demo

## 1. Two party
CONFIGFILE is the config json file. You can found the example file here: "configs/two_party_config.json".
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
$ cargo run --bin two_party_ecdsa <party_index> <CONFIGFILE>
```
*Please start all nodes before connect.

### (a) Step 1: connect

Connect two parties.
```
>> Connect
```

### (b) Step 2: KeyGen

KeyGen Begin

* Please run keygen by party 0.
```
>> keygen
```

### (c) Step 3: sign
* Please run sign by party 0.
```
>> sign
```

### (d) Step 4: Quit

Disconnect peers.
```
>> q
```

## 2. Multi party keygen

CONFIGFILE is the config json file. You can found the example file here: "configs/config_3pc.json".
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
$ cargo run --bin multi_party_ecdsa_keygen <party_index> <CONFIGFILE>
```

*Please start all nodes before connect.

### (a) Step 1: KeyGen connect

Connect all keygen peers.
```
>> multikeygenconnect
```

### (b) Step 2: KeyGen

KeyGen Begin
* Please run keygen by party 0.
```
>> keygen
```

### (c) Step 3: KeyGen Quit

Disconnect peers.
```
>> q
```


## 3. Multi party sign

CONFIGFILE is the config json file. You can found the default file here: "p2p/examples/config.json".
```
$ cargo run --bin multi_party_ecdsa_sign <party_index> <CONFIGPATH>
```

*Please start all nodes before connect.

### (a) Step 1: Sign connect

Connect the subset peers.
```
>> multisignconnect
```

### (b) Step 2: Sign Begin
* Please run sign by party 0.

```
>> sign
```

### (c) Step 3: Sign Quit

Disconnect peers.
```
>> q

```