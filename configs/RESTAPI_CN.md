
[TOC]



- 两方： $N(N = 2)$。
- 多方： $N(N\gt 2)$。


## Start Server

以 HTTP 服务的形式启动 $N$ 个节点。

> 启动 HTTP 服务的时候，**不会**初始化各节点之间的网络，而是通过调用 `/connect` API 初始化各节点的网络，通过调用 `/disconnect` API 释放各节点的网络。


```sh
./mpc_ecdsa_web <parties> <party-id> <port> <config-file>
#eg: ./mpc_ecdsa_web 0 8080 config.json
```

| parameter   | description              |
| ----------- | ------------------------ |
| parties     | N                        |
| party-id    | [0, N)                   |
| port        | HTTP Server Port         |
| config-file | [ref here](#config-file) |

> 使用参考 [README.md](../README.md) 或者 [run_web.sh](../run_web.sh)。


### config-file

对原来的配置文件进行了优化，通用，每方都一样。例如：


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
    ],
    "message": "xxxxxxxxxxxx",
    "subset": [
        0,
        1,
        2
    ]
}
```

> 如果是两方，share_count/threshold/subset 无效（即不会使用）。
> message 历史遗留，无效。


## API

通用 RESPONSE

```json
{
  "code":0,
  "desc":"Success",
  "data":[]
}
```

| field | type    |
| ----- | ------- |
| code  | integer |
| desc  | string  |
| data  | array   |


### connect


```
/connect
```

初始化各节点之间的网络。

- REQUEST

暂无。

- RESPONSE

通用。


### disconnect


```
/disconnect
```

释放各节点之间的网络。


- REQUEST

暂无。


- RESPONSE

通用。



### keygeninit


目前（多方） KeyGen 接口用一次后，不能使用第二次，故提供此 API。

> Q：为何不在 KeyGen 之前内部调用 keygeninit 呢？
> A：因为必须保证各方在 KeyGen 之前都 keygeninit 完成了。


```
/keygeninit
```


- REQUEST

暂无。

- RESPONSE

通用。

### keygen


```
/keygen
```

- REQUEST

暂无。


- RESPONSE

data 字段[参考这里](#keygen-response)。

### signinit

理由同 keygeninit。

```
/signinit
```

- REQUEST


| field | type   |
| ----- | ------ |
| msg   | string |

- RESPONSE

通用。

### sign

```
/sign
```

- REQUEST

暂无。


- RESPONSE


data 字段[参考这里](#sign-response)。


### getkey


返回生成的 key。


```
/getkey
```


### getsignature


返回生成的 signature。

```
/getsignature
```



## Appendix




### keygen-response

这里是一个三方的 KeyGen 返回值。$P_i$ 代表对应的节点。

$P_0$

```json
[
  {
    "public_share": {
      "x": "1adc07358c7410d6fa3658202bbd7f19f9d80d951b94c5056f7828be2b168bf2",
      "y": "8783d82935fd61a7f713a6264a0ec741271a7064bd1af76a43e5f6ab9637f8c1"
    },
    "secret_share": "65878e516f7ea2be56cde3d409b41a5cbe8391b7031db155f1f8369f0142eaab"
  },
  {
    "cl_pub_key": {
      "a": "b4f07fb5634e3d4a80c45e0a839c498e528a2f31ed941dbcfe03cc52756b478f25f20ca9fa48124fa3f2d55dde23693cc67b97b4717227dbbe64f5f277ec1f5de77b0923fa8324a65f9c9edd6c3e29706275b604494b5e4a4962f0699793f7892ebc3a6044c16229ef224d87baa7865bb6d579fb",
      "b": "622e014a5143de31338725d34983b182a336096b8ffe1323ad278fbc5139bf9b61138e1bf150ae1c5b3ead47cec25aecad6cc1a1bbdd619859488b50821908f41b79e4b29b5e0e01620b11e8983bcdcae4bd4e76aa8c5e01130224cfa5cc53ce06c49c2d19803fc682d303cafa1da60fec3e4b01",
      "c": "299bb4c18719439ed02e23876cb9182cdf8cbaef286b8a5ef33fddf0259cbe229836d278cf49b1cba9fc6049798a0b208127eb0f13415bd0053c73b19f3d88a8458f662adbe67629896ffb65fc14472cbd9b6abf12c5499458d4154d9032f010b531d94ad9b35fbddbbe357a35496a430830ca8d3"
    },
    "cl_priv_key": "42e8a9e4a6f6c954f15baf082ebca95ca8cfc9d656861909d596478e721000a0aa39527c46efc33a3949f2486ad663581f3719b200cbdb0ebdbb5dc14b5224cd0b693ac84c6c3e74f991759e0faf354af9a3331bfa59af6ba4d73"
  },
  {
    "x": "e5b3cf394e213b788c9ba6245a72298404f5b251c677f88a9c572e0040da9661",
    "y": "7052c244c93e727f969542bc0b4abe287cba832bc387464c61217b453a5a8ab"
  },
  "4ddfa6cf204532085951ec9e152c2b9820275e06859dacc9e4f3913452ade223",
  {
    "0": {
      "x": "2f7585c24126cf127844f8c3684f5125f8a18f620f9a03c4b77fe081f815ac2e",
      "y": "ecfb5623ff2b79dcdf2576c23bb927fb30bae101ec00d157253ac4951ce77c50"
    },
    "2": {
      "x": "37fd5373aa66bef385136a0950de11620a1d01b449a89230e0e2ca97d341d71",
      "y": "620abbdf173c591b9ddaf7b3c3e4d454e85fad8b1e834cd8d8c3c7b425d05f09"
    },
    "1": {
      "x": "a621fad574d7e93d275bc4b1d5064b8a908f0927c0871674f30df3c7d52277e9",
      "y": "e165b20af4a6aa7ae2b0529512e3d342c4f8bb4ef4fe72168cdbd7ca03a66994"
    }
  },
  {
    "2": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "71e0247b989985b394b2700a719b2145cad13fdb475a4c77bc17ba8de3523a95",
          "y": "8d1b2bf183bbe2a613532e74f87cc4ab1253c42dc744767cbb4bdc81b1c334b0"
        },
        {
          "x": "f6f11c45a44e4b70ea3b71c1229580e64557ea02ecf571ba10a0a1974e8d557e",
          "y": "3ba8d0e2fee1c5fd20f619399d18e6c163fa267e3fdd2eeb20953d3706ba725e"
        },
        {
          "x": "db7bb6ba40dca25e9004262169c5ac9e0b8268f0b7c4ef6fe9421a07ee51b7a3",
          "y": "7a07aeb994ce08c96f0cee8263a8826ac1a4bc953488b9b526c5b5e9dd68ffa2"
        }
      ]
    },
    "0": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "d21bb4207e15c9ae8fb83f51caacef62e504a116306b16d28985460e7c807af",
          "y": "a00de4953abe33ba55090c617fb0ee4ebc7d19fb45efb893e19dc5337e848136"
        },
        {
          "x": "132ee74447adafea298e788dfce906c18342935e51832fd2bb478ce5073682e8",
          "y": "daa71fb8a8ed083d15be49299d60f323d7ead5e56506d2e1e7186b6afdc1eb0"
        },
        {
          "x": "2e77190f5c2b40b9181b8be42a88ba76b728b97be888371b62db6834649044cd",
          "y": "ec2336ef366699867b89ea93d7b448a2d2f22a68444997164995fe9d824a5aa5"
        }
      ]
    },
    "1": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "7ea897704ca0657de73ea100a8a6aebb2233e63a877ccc4f3620509e2c5e818d",
          "y": "ab452d0410578e964693aa4bbeca162f411c9cb4a0ce8217be488ddc01dc73e5"
        },
        {
          "x": "41a321abace870fa7de49d42978955c48ec52f485983dbfc9901d24676b0bea2",
          "y": "6a7160771fc26c71c16cd8a515e6d1fa2701895e84ff67f92e022bbe0be13575"
        },
        {
          "x": "6b3969e481ec359cd0c55387529d80ad307454f08e9c2a7045f3a7d9fcd62feb",
          "y": "72938b33b195e525cb1b5a47004e4e730a899bc0e876317c1ca9bef16d6f2205"
        }
      ]
    }
  }
]
```

$P_1$


```json
[
  {
    "public_share": {
      "x": "6dfea30df5d7aabee6eaf128e0110340da36543bedf3c9baab37910111922bba",
      "y": "2cdfa1e7489fc6a3427ff404e59cc2eb7fa3e78d2ab5c675514f9b1f5d67bf39"
    },
    "secret_share": "d02ad9e70f511ab5b3a26ff2c7b4ba091d56935a6bf9504e4d5895527f88a17b"
  },
  {
    "cl_pub_key": {
      "a": "1206febdae19e7b6cc7e87ac533577eb75288ee8828ef5fac311c995d1b7ee67a3793b6a2271bc090f43e0bd11faf7de0a02596124942b8292cb240aa5c47ad51d2d8f7ce7163eb40d2f039590c0677388d61c9703b260aac5ba4016553a0ecf9251490566cdcd41423003f7cdacaeaf0a79cd325",
      "b": "-6b7e0fb91ab77fdf45a8505d8001a2a1f9d284df8e352bc6300db6f309f3aac60a272b55771076f976beec3eb33cc7f9d9f3dc8d0c88af47d3f2da8ff94e65b256a916fd40d35a85bd6188b7a792a8ea51070c29b3743b8b2348ca81b2304902045d58570c6ed928f25c8f06af814947475833d3",
      "c": "1a347b049e3ead7dcba97e2ae421257b954ef42a940ba5e387665ba4435da9ed36bb77427e4953c373c67e69f83d6d0a78e02fa28c1bbe6cc5869a0541267e6e95aad8dc2556c573689dbc4c9c40660552f294d8924ee302ebfdb9e321714e63eaad668823ad78ed300560b4a537d38764be8497f"
    },
    "cl_priv_key": "4af2a225550bb0c0059b076a2ec6143b9cffae7a8df78fd30eb4601e567b011ceaed6e79803798578e36a90fad3df8f7a4a74f942e235203af65e4e6188f17433ec093afb02d4dd93f33ffb7b1cba69f26f3b8ad941135be1c75b"
  },
  {
    "x": "e5b3cf394e213b788c9ba6245a72298404f5b251c677f88a9c572e0040da9661",
    "y": "7052c244c93e727f969542bc0b4abe287cba832bc387464c61217b453a5a8ab"
  },
  "6b7bb2da2a764d4b90669910c0a7578add6fc91b4b2ad8874fdc5765180c609e",
  {
    "1": {
      "x": "a621fad574d7e93d275bc4b1d5064b8a908f0927c0871674f30df3c7d52277e9",
      "y": "e165b20af4a6aa7ae2b0529512e3d342c4f8bb4ef4fe72168cdbd7ca03a66994"
    },
    "2": {
      "x": "37fd5373aa66bef385136a0950de11620a1d01b449a89230e0e2ca97d341d71",
      "y": "620abbdf173c591b9ddaf7b3c3e4d454e85fad8b1e834cd8d8c3c7b425d05f09"
    },
    "0": {
      "x": "2f7585c24126cf127844f8c3684f5125f8a18f620f9a03c4b77fe081f815ac2e",
      "y": "ecfb5623ff2b79dcdf2576c23bb927fb30bae101ec00d157253ac4951ce77c50"
    }
  },
  {
    "2": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "71e0247b989985b394b2700a719b2145cad13fdb475a4c77bc17ba8de3523a95",
          "y": "8d1b2bf183bbe2a613532e74f87cc4ab1253c42dc744767cbb4bdc81b1c334b0"
        },
        {
          "x": "f6f11c45a44e4b70ea3b71c1229580e64557ea02ecf571ba10a0a1974e8d557e",
          "y": "3ba8d0e2fee1c5fd20f619399d18e6c163fa267e3fdd2eeb20953d3706ba725e"
        },
        {
          "x": "db7bb6ba40dca25e9004262169c5ac9e0b8268f0b7c4ef6fe9421a07ee51b7a3",
          "y": "7a07aeb994ce08c96f0cee8263a8826ac1a4bc953488b9b526c5b5e9dd68ffa2"
        }
      ]
    },
    "0": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "d21bb4207e15c9ae8fb83f51caacef62e504a116306b16d28985460e7c807af",
          "y": "a00de4953abe33ba55090c617fb0ee4ebc7d19fb45efb893e19dc5337e848136"
        },
        {
          "x": "132ee74447adafea298e788dfce906c18342935e51832fd2bb478ce5073682e8",
          "y": "daa71fb8a8ed083d15be49299d60f323d7ead5e56506d2e1e7186b6afdc1eb0"
        },
        {
          "x": "2e77190f5c2b40b9181b8be42a88ba76b728b97be888371b62db6834649044cd",
          "y": "ec2336ef366699867b89ea93d7b448a2d2f22a68444997164995fe9d824a5aa5"
        }
      ]
    },
    "1": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "7ea897704ca0657de73ea100a8a6aebb2233e63a877ccc4f3620509e2c5e818d",
          "y": "ab452d0410578e964693aa4bbeca162f411c9cb4a0ce8217be488ddc01dc73e5"
        },
        {
          "x": "41a321abace870fa7de49d42978955c48ec52f485983dbfc9901d24676b0bea2",
          "y": "6a7160771fc26c71c16cd8a515e6d1fa2701895e84ff67f92e022bbe0be13575"
        },
        {
          "x": "6b3969e481ec359cd0c55387529d80ad307454f08e9c2a7045f3a7d9fcd62feb",
          "y": "72938b33b195e525cb1b5a47004e4e730a899bc0e876317c1ca9bef16d6f2205"
        }
      ]
    }
  }
]
```

$P_2$


```json
[
  {
    "public_share": {
      "x": "43447c24c83166d8c854861b8093029d4aabf2726f9e40aaaada59e1a68eebd7",
      "y": "63e6a2d37c54b61a0c35e965bca6cc05dd8f92f3e957534c3e7502e6365c1214"
    },
    "secret_share": "43def40497c29910a1c762b8104c79eff9bedf9c92133fef8160a67fac2d4c57"
  },
  {
    "cl_pub_key": {
      "a": "6e323f5cde0432ce4c7caa52a5dab1fdd345343910e2dfe41f478229775d3db3660f92393fb6404d2eae0d588e47b05a94a6d096c71643becd03ca4ba4f244a8a59573dd54da511a14af275bb05682224b4696c59784261e3650ef41389f96482df99c7516350b0ba303a3c15be95ada0f14069d",
      "b": "-3dd701b79a1814761cb6e2b0e88f2198ddc5abdd1c7786fa6d636c89cc65384fd7d4ded5eaa6689e3fe94c52ac97ab0ed243ed5d17fb33413d7159462b8e79ce1e54d6cbd025d46256c58d4e4b9c3ec2b6a34c66df718101145a05f47fd11c27166d8c4b8a1d7db267ceb6cce940a80ad7487bc9",
      "c": "437ebee3c0d4d91e341181f65788a8f53e680a048c5f98123eb71a0935bb47c74f21b27c8a9eb5b4d2e3e43a69b5eedcf415583a0b025fac16d9634d887212549f34a600be09b652bead3bd9039801296aaba450797bf011080348d45aa4cdec7115fc5f0267c7602178ef085da97378cdd180819"
    },
    "cl_priv_key": "4c619156d0c0634897488d471d16d2ce630cc1b1f119218a0507a3ba9f7a366999df7a74a42229b65b9a968ae9a8e6adee0ceaca2d94a5a7f76e587c2befc9bf3cad4c2cd6def5449cce5643ed29bdf13c4051f86b8a4d43b714b"
  },
  {
    "x": "e5b3cf394e213b788c9ba6245a72298404f5b251c677f88a9c572e0040da9661",
    "y": "7052c244c93e727f969542bc0b4abe287cba832bc387464c61217b453a5a8ab"
  },
  "374b9b54b5ce62ccbd05fb0ab4d2d27931fdeb136a780353870572e6d49be421",
  {
    "1": {
      "x": "a621fad574d7e93d275bc4b1d5064b8a908f0927c0871674f30df3c7d52277e9",
      "y": "e165b20af4a6aa7ae2b0529512e3d342c4f8bb4ef4fe72168cdbd7ca03a66994"
    },
    "2": {
      "x": "37fd5373aa66bef385136a0950de11620a1d01b449a89230e0e2ca97d341d71",
      "y": "620abbdf173c591b9ddaf7b3c3e4d454e85fad8b1e834cd8d8c3c7b425d05f09"
    },
    "0": {
      "x": "2f7585c24126cf127844f8c3684f5125f8a18f620f9a03c4b77fe081f815ac2e",
      "y": "ecfb5623ff2b79dcdf2576c23bb927fb30bae101ec00d157253ac4951ce77c50"
    }
  },
  {
    "1": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "7ea897704ca0657de73ea100a8a6aebb2233e63a877ccc4f3620509e2c5e818d",
          "y": "ab452d0410578e964693aa4bbeca162f411c9cb4a0ce8217be488ddc01dc73e5"
        },
        {
          "x": "41a321abace870fa7de49d42978955c48ec52f485983dbfc9901d24676b0bea2",
          "y": "6a7160771fc26c71c16cd8a515e6d1fa2701895e84ff67f92e022bbe0be13575"
        },
        {
          "x": "6b3969e481ec359cd0c55387529d80ad307454f08e9c2a7045f3a7d9fcd62feb",
          "y": "72938b33b195e525cb1b5a47004e4e730a899bc0e876317c1ca9bef16d6f2205"
        }
      ]
    },
    "2": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "71e0247b989985b394b2700a719b2145cad13fdb475a4c77bc17ba8de3523a95",
          "y": "8d1b2bf183bbe2a613532e74f87cc4ab1253c42dc744767cbb4bdc81b1c334b0"
        },
        {
          "x": "f6f11c45a44e4b70ea3b71c1229580e64557ea02ecf571ba10a0a1974e8d557e",
          "y": "3ba8d0e2fee1c5fd20f619399d18e6c163fa267e3fdd2eeb20953d3706ba725e"
        },
        {
          "x": "db7bb6ba40dca25e9004262169c5ac9e0b8268f0b7c4ef6fe9421a07ee51b7a3",
          "y": "7a07aeb994ce08c96f0cee8263a8826ac1a4bc953488b9b526c5b5e9dd68ffa2"
        }
      ]
    },
    "0": {
      "parameters": {
        "threshold": 2,
        "share_count": 3
      },
      "commitments": [
        {
          "x": "d21bb4207e15c9ae8fb83f51caacef62e504a116306b16d28985460e7c807af",
          "y": "a00de4953abe33ba55090c617fb0ee4ebc7d19fb45efb893e19dc5337e848136"
        },
        {
          "x": "132ee74447adafea298e788dfce906c18342935e51832fd2bb478ce5073682e8",
          "y": "daa71fb8a8ed083d15be49299d60f323d7ead5e56506d2e1e7186b6afdc1eb0"
        },
        {
          "x": "2e77190f5c2b40b9181b8be42a88ba76b728b97be888371b62db6834649044cd",
          "y": "ec2336ef366699867b89ea93d7b448a2d2f22a68444997164995fe9d824a5aa5"
        }
      ]
    }
  }
]
```


### sign-response

这里是一个签名返回值。

```json
[
  {
    "s": "6dc5a4d83c9bc54ba3a9c4bb1d6fb679715157af29fbe563403c594f2d277ad3",
    "r": "f00bf0122625bd445212b7eb5f352e903b6983d63f9e8985a07e7136a6b406f7"
  }
]
```

### TODO

- 加入性能统计。
- 或考虑更换 IO。
- 其它细节处理与工程优化。

