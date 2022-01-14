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
$ cargo run --bin two_party_ecdsa_one -- --help

USAGE:
    two_party_ecdsa_one [FLAGS] [OPTIONS]

FLAGS:
    -h, --help              Prints help information
    -o, --online_offline    Sign Model
    -V, --version           Prints version information

OPTIONS:
    -c, --config_file <config_file>    Config Path [default: ./configs/two_party_config.json]
        --level <level>                Log level [default: DEBUG]
        --log <log>                    Log path [default: /tmp]
    -m, --message <message>            Message to sign [default:
                                       eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d]
```

### 1.2 two_party_ecdsa cli example
Normal Sign Model
```shell
$ cargo run --bin two_party_ecdsa_one -- --config_file ./configs/two_party_config.json  --message eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d


$ cargo run --bin two_party_ecdsa_two -- --config_file ./configs/two_party_config.json  --message eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d
```
Online_Offline Sign Model
* No need to specify message at begining.
```shell
$ cargo run --bin two_party_ecdsa_one -- --config_file ./configs/two_party_config.json  --online_offline


$ cargo run --bin two_party_ecdsa_two -- --config_file ./configs/two_party_config.json  --online_offline
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

### (d) Step 3*: sign refresh
After refresh, you can sign again.

```shell
>> tworefresh eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d ./keygen_result0.json
```
* tworefresh is command
* "eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d" is the new message to sign.
* "./keygen_result0.json" is the file path of new keygen-result.

### (e) Step 4: set message (only used in online-offline model)
* Please set message before online phase and run by both parties.
```shell
>> setmessage eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d
```
### (f) Step 5: sign online phase (only used in online-offline model)
```shell
>> signonline
```

### (g) Step 4: Quit

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
$ cargo run --bin multi_party_ecdsa_keygen -- --help

USAGE:
    multi_party_ecdsa_keygen [OPTIONS] --index <index>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config_file <config_file>    Config Path [default: ./configs/config_3pc.json]
    -i, --index <index>                My index
        --level <level>                Log level [default: DEBUG]
        --log <log>                    Log path [default: /tmp]
```

### 2.2 keygen cli example
```shell
$ cargo run --bin multi_party_ecdsa_keygen -- --config_file ./configs/config_3pc.json --index 0
```

*Please start all nodes before connect.

### (a) Step 1: KeyGen connect

Connect all keygen peers.
```
>> connect
```

### (b) Step 2: KeyGen

KeyGen Begin
* Please run keygen by party 0.
```
>> keygen
```

Keygen Result
public key:
```json
{
	"pk": {
		"x": "f5dd9621cf8bbfc8a54c94fa21e389ad38648a4f6b5aee12b7901e1714ed7397",
		"y": "f6adef11d25d504b611f252656995c826adc28a74433c936b29ee7685288ccd8"
	},
	"share_pks": {
		"1": {
			"x": "5ba66927dce0037801b3ec82b803ddff4994eacebae0d21209b967bbf26a6780",
			"y": "658e84279d51fc4d6b9fc1cc7c35cc095ffb3e2cfad8cd765a89e5d7ec23732f"
		},
		"0": {
			"x": "fc4d99451352fc319a1fc70070d945d807c7f56e443ad6802a45b4a47897f05c",
			"y": "6f81b550d35693651acfbc898036ff894e99f50260ec694eda7dbd0bfadb9a4"
		},
		"2": {
			"x": "fe5b9d0cbcca084ec5a5ba22860ff6c50111b8eae05ae7eb5616c006f0019f7b",
			"y": "b4a9c38eb570ae9124c19772caf7d51900dce3c25b27f5637856cf7eec4a7333"
		}
	},
	"vss": {
		"0": {
			"parameters": {
				"threshold": 1,
				"share_count": 3
			},
			"commitments": [{
				"x": "684fa0c684427045801346868bc9ff868664516e49f32c194baee415241841ac",
				"y": "b2209c0a12e07e6c4251d625776a379adba431eb4dd78f24423f9fef0561896"
			}, {
				"x": "f15e7da61e08c671e39e39550c90b6c0cb67e448d6083b79b370af0930b13b32",
				"y": "54474395284a66f85384de36ffe857bac74441acc27768628a03b18552f86ef9"
			}]
		},
		"1": {
			"parameters": {
				"threshold": 1,
				"share_count": 3
			},
			"commitments": [{
				"x": "e92943ac1853d1f16f2c67a7bb9a718c94ed6858c09e6f94813d2ee8e2d7d9a",
				"y": "d7686cf9f779de3041b4411c533db6f9f240e2f32159915d2cc8bf60d395df05"
			}, {
				"x": "943cc31fb8ea81565c3d4fa41956a804d5c9ad79128a72dec069604b6f113d3f",
				"y": "9b1b979b2afdb1f6de4f184dafe900b5a53bb9359619f30f2fb2101a415b20fe"
			}]
		},
		"2": {
			"parameters": {
				"threshold": 1,
				"share_count": 3
			},
			"commitments": [{
				"x": "4d445e0aa10cda4b68b615e7b8877e1e027b6cca9a37a9b3def3f69d05c58f95",
				"y": "164cee3c7c7a3e3a67fe95cc92b024c0d5d3b2d062888428e60fd8dc8caa019b"
			}, {
				"x": "5d3da9b3e78ac632884911cd5693edf49654f517d0b431cff0aa4768e69bbced",
				"y": "665997d5b7249bcace11d5747638835af7264d7cb1fe3f6156a7e7985a1152e1"
			}]
		}
	}
}
```
private key:
```json
{
"cl_sk": "19cf0570bc45955ea9974ca39931c869519bcaeef29c47a1ccfa6624009653bb912cc834595f2dfd32650bbd36939bfa8ef6002557aa9eb793173bcbfc03d1e1af055dcae696d750690cd41f9bee3496ed6eaebd7cb9834fcce0a458153df3755cfa5a7832b1c235e",
"ec_sk": "c70af11e3ab3b38803b96cdf2cfc8bf4c3aa1d2cfaa3144dec96fadfbb2cf04c",
"share_sk": "2ed299d44bf29d96b06fdafe49b9a6f1e77e18ac546601cccb12cc178becbc55"
}
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
$ cargo run --bin multi_party_ecdsa_sign -- --help

USAGE:
    multi_party_ecdsa_sign [FLAGS] [OPTIONS] --index <index>

FLAGS:
    -h, --help              Prints help information
    -o, --online_offline    Sign Model
    -V, --version           Prints version information

OPTIONS:
    -c, --config_file <config_file>            Config file [default: ./configs/config_3pc.json]
    -i, --index <index>                        My index
    -k, --keygen_path <keygen_path>            Keygen private result path [default: ./]
        --level <level>                        Log level [default: DEBUG]
        --log <log>                            Log path [default: /tmp]
    -m, --message <message>                    Message to sign [default:
                                               eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d]
    -p, --pub_keygen_path <pub_keygen_path>    Keygen public result path [default: ./]
    -s, --subset <subset>...                   Participants index
```

### 3.2 sign cli example
Normal Sign Model
```shell
$ cargo run --bin multi_party_ecdsa_sign -- --config_file ../configs/config_3pc.json --index 0 --message eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d --subset 0 1 --pub_keygen_path ./keygen_pub_result0.json --keygen_path ./kengen_priv_result0.json
```
Online_Offline Sign Model
* No need to specify message at begining.
```shell
$ cargo run --bin multi_party_ecdsa_sign -- --config_file ../configs/config_3pc.json --index 0 --subset 0 1 --keygen_pub_path ./keygen_pub_result0.json --keygen_path ./kengen_priv_result0.json --online_offline
```

*Please start all nodes before connect.

### (a) Step 1: Sign connect

Connect the subset peers.
```
>> connect
```

### (b) Step 2: Sign Begin
```
>> sign
```

Signature result
```json
{
	"s": "6ce8fc4a0d5f8028562c4e649c7bf54b4196659bc9f770e2a93e7933512efb3b",
	"r": "4a70fd7b22ae25e19c14c7d95c897b32196cf86690008f9b5175e8063f1a2940"
}
```

### (d) Step 3*: sign refresh
After refresh, you can sign again.

```shell
>> multirefresh eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1f ./keygen_pub_result0.json ./keygen_priv_result0.json 0 1
```
* multirefresh is command
* "eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d" is the new message to sign.
* "./keygen_pub_result0.json" and "./keygen_priv_result0.json" are the file paths of new public keygen result and private keygen result.
* "0 1" are the new subset member indexes.

### (e) Step 4: set message (only used in online-offline model)
* Please set message before online phase and run by all parties.
```shell
>> setmessage eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d
```
### (f) Step 5: sign online phase (only used in online-offline model)
```shell
>> signonline
```
### (d) Step 3: Sign Quit

Disconnect peers.
```
>> q

```

## 4.Multi party keyrefresh

Use the same config file as keygen.

### 4.1 How to use ecdsa_keyrefresh
```shell
$ cargo run --bin ecdsa_keyrefresh -- --help

USAGE:
    ecdsa_keyrefresh [OPTIONS] --index <index>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config_file <config_file>            Config Path [default: ./configs/config_3pc.json]
    -i, --index <index>                        My index
    -k, --keygen_path <keygen_path>            Keygen result path [default: ./]
        --level <level>                        Log level [default: DEBUG]
        --log <log>                            Log path [default: /tmp]
    -p, --pub_keygen_path <pub_keygen_path>    Keygen result path [default: ./]
    -t, --threshold_set <threshold_set>...     Participants index
```
### 4.2 Key refresh cli example
```shell
cargo run --bin ecdsa_keyrefresh -- --config_file ../configs/config_3pc.json --index 0  --threshold_set 0 1 --keygen_pub_path ./keygen_pub_result0.json --keygen_path ./kengen_priv_result0.json
```

### (a) Step 1: Key refresh connect

Connect the subset peers.
```
>> connect
```

### (b) Step 2: Key Refresh Begin
```
>> keyrefresh
```
