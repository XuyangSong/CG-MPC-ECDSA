# Run ECDSA demo

## 1. Two party
 You can found the example config file here: "configs/two_party_config.json".
```json
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
    ]
}
```

### 1.1 How to use two_party_ecdsa
```shell
$ ./two_party_ecdsa --help

USAGE:
    two_party_ecdsa --config_path <config_path> --index <index> --message <message>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config_path <config_path>    Config Path
    -i, --index <index>                My index
    -m, --message <message>            Message to sign
```

### 1.2 two_party_ecdsa cli example

```shell
$ ./target/debug/two_party_ecdsa --config_path ./configs/two_party_config.json --index 0 --message eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d
```

*Please start all nodes before connect.

### (a) Step 1: connect

Connect two parties.
```shell
>> Connect
```

### (b) Step 2: KeyGen

KeyGen Begin

* Please run keygen by party 0.
```shell
>> keygen
```

### (c) Step 3: sign
* Please run sign by party 0.
```shell
>> sign
```

### (d) Step 4: Quit

Disconnect peers.
```shell
>> q
```

## 2. Multi party keygen

You can found the example config file here: "configs/config_3pc.json".
```json
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
    ]
}
```
Specify the party_index, party_index should be less than the total share counts.

### 2.1 How to use multi_party_ecdsa_keygen

```shell
$ ./multi_party_ecdsa_keygen --help

USAGE:
    multi_party_ecdsa_keygen --config_path <config_path> --index <index>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config_path <config_path>    Config Path
    -i, --index <index>                My index
```

### 2.2 keygen cli example
```
$ ./multi_party_ecdsa_keygen --config_path ./configs/config_3pc.json --index 0
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

Use the same config file as keygen.

### 3.1 How to use multi_party_ecdsa_sign
```shell
$ ./multi_party_ecdsa_sign --help

USAGE:
    multi_party_ecdsa_sign [OPTIONS] --config_path <config_path> --index <index> --message <message>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config_path <config_path>    Config Path
    -i, --index <index>                My index
    -m, --message <message>            Message to sign
    -s, --subset <subset>...           Paticipants index
```

### 3.2 sign cli example
```
$ ./multi_party_ecdsa_sign --config_path ./configs/config_3pc.json --index 0 --message eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d --subset 0 1
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