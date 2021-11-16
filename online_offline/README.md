# Run online-offline ECDSA examples

## 1. Two party
```shell
$ cargo run --bin online_offline_two_party_ecdsa_one -- --config_path ./configs/two_party_config.json

$ cargo run --bin online_offline_two_party_ecdsa_two -- --config_path ./configs/two_party_config.json
```

*Please start all nodes before connect.

### Step 1: connect

Connect two parties.
```shell
>> Connect
```

### Step 2: KeyGen

KeyGen Begin

* Please run keygen by party 0.
```shell
>> keygen
```

### Step 3: Sign (offline phase)
* Please run sign by party 0.
```shell
>> signoffline
```
### Step 4: Sign (online phase)
* Please run sign by party 1.
* Need to input the message used to sign.
```shell
>> signonline eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d
```
### Step 5: Quit

Disconnect peers.
```shell
>> q
```

## 2. Multi party keygen

```shell
$ cargo run --bin online_offline_multi_party_ecdsa_keygen -- --config_path ./configs/config_3pc.json --index 0
```

*Please start all nodes before connect.

### Step 1: KeyGen connect

Connect all keygen peers.
```
>> connect
```

### Step 2: KeyGen

KeyGen Begin
* Please run keygen by party 0.
```
>> keygen
```

### Step 3: KeyGen Quit

Disconnect peers.
```
>> q
```

## 3. Multi party sign

Use the same config file as keygen.

```shell
$ cargo run --bin online_offline_multi_party_ecdsa_sign -- --config_path ../configs/config_3pc.json --index 0  --subset 0 1 --keygen_path ./keygen_result0.json
```

*Please start all nodes before connect.

### Step 1: Sign connect

Connect the subset peers.
```
>> connect
```

### Step 2: Sign (offline phase)
```
>> signoffline
```

### Step 2: Sign (online phase)
```
>> signonline eadffe25ea1e8127c2b9aae457d8fdde1040fbbb62e11c281f348f2375dd3f1d
```

### Step 3: Sign Quit

Disconnect peers.
```
>> q

```