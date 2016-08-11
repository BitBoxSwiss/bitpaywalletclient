bitpaywalletclient – A C++ client and library to access Bitpays wallet service (the backend of Copay)
=====================================================================================================

[![Build Status](https://travis-ci.org/digitalbitbox/bitpaywalletclient.svg?branch=master)](https://travis-ci.org/digitalbitbox/bitpaywalletclient)  [![Coverage Status](https://coveralls.io/repos/digitalbitbox/bitpaywalletclient/badge.svg?branch=master&service=github)](https://coveralls.io/github/bitpaywalletclient/bitpaywalletclient?branch=master)


Dependencies
----------------
* libcurl

Internal dependencies (included as subtree)
-------------------------------------------
* libbtc (bitcoin library)
* secp256k1 (ECC secp256k library)
* UniValue (JSON library)

How to Build
----------------
```
./autogen.sh
./configure
make
```
