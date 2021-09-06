## Sharing
```
char* key_gen()
```
**Generate wallet keys**
*Output*
key: a share of the key used to sign
[{"cl_pub_key": " ",   
   "cl_priv_key":" "},
   {"public_share":  " ",
     "secret_share": " "},{"x":"7a89d12a5316672976517db4d0ce7841cce74c52eb130682020e8f5e34ba682d","y":"3a04e3a711c29a6d3bb092acee80c80787bc91889623f700b326e0fc9d0c47f5"},"77a37fd8aa4e3138f746ff8c49a3e6f4936809073465a449ed94fa1097d103a7",
     {"0":
               {"x":"176e35077428dc84e0475388cece8b5faba0cc8ec32d5124981610a1f07f9da6","y":"649a894149aa24fcf28365119b2a2ca39e1303f91f5804b704073ee8e33f47ab"},
       "2":
               {"x":"e2fff9f8077eaae5e72c49e1f3addc16f52c6ecb82599951263059467df780f", 
                "y":"498be956f15242767e856810b30e00cb3987ff7e52630c4796c5511d75e8d6f0"},
       "1":
               {"x":"474cde7526bdfa5bb7ce0ede8ae8260f8edc0a13850a80cf152d6b6fc4db66c1","y":"26ae7a4872be59ade204e61e2256ad60379778449233f0a5b4f1c7aef6f150e8"}},
     {"1":
               {"parameters":{"threshold":2,"share_count":3},
               "commitments":
                          [{"x":"97153e08a6f1e9e7f27d7ec7cb0d488650565545062f1970dd445bfbd4cd3b2e","y":"5c072a8c86f4b5761502c190c8ba174faba7ecddff7052940643bc8274db8e58"},{"x":"d016388b325674b04deb56fcdb29c8dacdca5516308092c24bf2904d92bfbff2","y":"6adca34dbfdf7fd3fc2eace07d338659998e795255bd79bc423e1cfe86f72acb"},{"x":"a8528fcc9fa264223cdd0eba98e1d2bc161ebbb2125dd93d3c04b001cf916ccb","y":"ca57f4a8e16d8c2af46fa14e8c5aec388cd19effa58d43c266c07cc41083a5b4"}]},
        "2":
                {"parameters":{"threshold":2,"share_count":3},
                "commitments":
                         [{"x":"7422d0d070bd5b129c97bb21f77bfd7f1f9ddc927d5195976b605c869a044ade","y":"1a5bc2888860815f997fd3133d5c1edd79aaebb12e1f64557cfdebe95b3d25a9"},{"x":"749787dbd44610a65a7920710e4984a7012fd2818b882c5a6880d102c77f75a7","y":"743223dad1bd351ede3ccb480d3c492c66dab24b974060e4d4269193755e0adf"},{"x":"b14823cda3e4e05dfbe0525e13689d6099c8a24dd84c85b38e20c149fd15b3fc","y":"b3eb8ee066023ebd2201f84bfbd6b701aba76d028115cb238fc1916e8e45afd"}]},
        "0":{"parameters":{"threshold":2,"share_count":3},
                "commitments":
                        [{"x":"dfce522c29c7efade6ac36226a326691603b8d79c5ec0336a5a1315c8b81a25f","y":"d3e6d830eff6568de3add659ba74e27140b15a4c6bf9ac9ef1a2c57b235b51d8"},{"x":"dcc9c5ae90262fd766eaa9fefde5ee48703568c1377b7806a54f68cee35ec0e9","y":"c825813dd01d59e5eee9bc260fb8c091018cc67640115cc52a88b1b3baa28aa9"},{"x":"dd6a8f5cb35c631b8793ac96e04cc84af9c67209c63d85b0d93cf7e557c60e72","y":"87973f05a6c35156fecf3418b95ceed68c17176f2d7d58e509d69e2ad1fc0c25"}]}}]

```
char *key_share(uninptr_t thresshold, uintptr_t share_count, const char *key)
```
**Sharing wallet keys**
*Input*
'threshold': at least 'threshold + 1' members can reconstruct key.
‘sharecount’: the num of shares.
'key': key to be shared
Input 'key' json string format example:
  {"key":"76f3f440a601bb04dd3730cbec67baf987c96b1eed4b3258ecefcb3dc4ebd48c"}
 
 *Output*
 'vss_scheme': parameters and commitments generated in vss scheme
 'key_shares': shares of key
Output json string format example:
  {vss_scheme": {
  		"parameters": {
  			"threshold": 1,
  			"share_count": 3
  		},
  		"commitments": [{
  			"x": "6fb81e9d2c142cab62b497e22f4e145a629f1b7784500f955db7f8f5ed14da7d",
  			"y": "27f6234c28320d56434cffc12e58fd4880e89ac37da1ea85a0cd0710878961f7"
  		}, {
  			"x": "10f46c9524571d78dddb4b8c6416d962412fb1c4468b63d2e72c04bcff81be7f",
  			"y": "92e7204c16dc8e673e48863f91fb5d631451c2711266c325c9b9cd9d5f3f840b"
  		}]
  	},
  	"secret_shares": ["f1c27f89672aeca11dad2694c2cffd09b0d10ecae443ae7cb5d14d6b3375ca90", "341ef9e5cb5c7fb14fbb62cebd56f0adc4faa67dfae3dd21e436e3c9b7b87376", "767b74422f8e12c181c99f08b7dde45093d31b17c0ccac02d26ed8b50c315d9d"]
  }
}

## Restore one share
```
char* key_restore()
```

```
char* key_share_restore(*char key_shares, uninptr_t threshold, uninptr_t index)
```
**Restore a single lost key share**
*Input*
'key_shares': other shares of key
'threshold': at least 'threshold + 1' members can reconstruct key.
‘index’: the index of user need to restore key share
Input 'key_shares' json string format example:
 "key_shares": ["f1c27f89672aeca11dad2694c2cffd09b0d10ecae443ae7cb5d14d6b3375ca90", "341ef9e5cb5c7fb14fbb62cebd56f0adc4faa67dfae3dd21e436e3c9b7b87376"]
 
 *Output*
 'key_share_restored': key_share restored
Output json string format example:
{"key_share_restored": "f1c27f89672aeca11dad2694c2cffd09b0d10ecae443ae7cb5d14d6b3375ca90", "341ef9e5cb5c7fb14fbb62cebd56f0adc4faa67dfae3dd21e436e3c9b7b87376"}
## Refresh
```
char* key_refresh(*char constant_item, uninptr_t thresshold, uintptr_t share_coun)
```
**Refresh wallet keys, use new keys can generate correct signature**
*Input*
'constant_item': constant item of new polynomial, equals to the original polynomial
'threshold': at least 'threshold + 1' members can reconstruct key.
'sharecount’: the num of shares.
 
 *Output*
 'key': key: a share of the key used to sign

 ```
char* key_share_refresh(*char constant_item, uninptr_t thresshold, uintptr_t share_coun)
```
**Refresh key shares, use new key shares can reconstruct the same key**
*Input*
'constant_item': constant item of new polynomial, equals to the original polynomial
'threshold': at least 'threshold + 1' members can reconstruct key.
'sharecount’: the num of shares.
 
 *Output*
 'vss_scheme': parameters and commitments generated in vss scheme
 'key_shares': shares of key
## Sign
```
char* reconstruct_then_sign(*char key_shares, *char message,)
```