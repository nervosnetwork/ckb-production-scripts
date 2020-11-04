# ckb-anyone-can-pay

CKB anyone-can-pay lock.

[RFC Draft](https://talk.nervos.org/t/rfc-anyone-can-pay-lock/4438)

## Build

``` sh
make all-via-docker && cargo test
```

## Quick start

### Create

1, create a cell to receive UDT and CKB:

```
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash>
    }
    data: <UDT amount>
    type: <UDT>
}
```

2, create a cell to receive only CKB:

```
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash>
    }
    data: <empty>
    type: <none>
}
```

3, we can add minimum amount transfer condition:

```
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash> | <minimum CKB> | <minimum UDT>
    }
    data: <UDT amount>
    type: <UDT>
}
```

`minimum CKB` and `minimum UDT` are two optional args, each occupied a byte, and represent `10 ^ x` minimal amount. The default value is `0` which means anyone can transfer any amount to the cell. A transfer must satisfy the `minimum CKB` **or** `minimum UDT`.

If the owner only wants to receive `UDT`, the owner can set `minimum CKB` to `255`.

### Send UDT and CKB

To transfer coins to an anyone-can-pay lock cell, the sender must build an output cell that has the same `lock_hash` and `type_hash` to the input anyone-can-pay lock cell; if the input anyone-can-pay cell has no `data`, the output cell must also be empty.

```
# inputs
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash> | <minimum CKB: 2>
    }
    data: <empty>
    type: <none>
    capacity: 100
}
...

# outputs
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash> | <minimum CKB: 2>
    }
    data: <empty>
    type: <none>
    capacity: 200
}
...
```

### Signature

The owner can provide a secp256k1 signature to unlock the cell, the signature method is the same as the [P2PH](https://github.com/nervosnetwork/ckb-system-scripts/wiki/How-to-sign-transaction#p2ph).

Unlock a cell with a signature has no restrictions, which helps owner to manage the cell as he wants.
