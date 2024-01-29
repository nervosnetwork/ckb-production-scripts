# ckb production scripts

CKB scripts used in production.

### Build

```
git submodule update --init --recursive
make all-via-docker
```

### RFC and Deployment

* [sUDT](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md)
* [xUDT](https://github.com/nervosnetwork/rfcs/pull/428)

All scripts above are deployed on mainnet, see RFC for more details.

### Policy
* All scripts have been developed by the nervosnetwork team.
* Each script undergoes comprehensive review and audit processes to ensure quality and security.
* All scripts are deployed on the mainnet, with no capability for upgrading, guaranteeing stability and reliability.


### Omnilock
It is moved to a [new repo](https://github.com/cryptape/omnilock).

### Anyone Can Pay
It is moved to a [new repo](https://github.com/cryptape/anyone-can-pay).

