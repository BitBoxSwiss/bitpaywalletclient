/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
*/

#include "bitpaywalletclient-config.h"

#include <btc/ecc.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

static struct option long_options[] =
{
    {"privkey", required_argument, NULL, 'p'},
    {"pubkey", required_argument, NULL, 'k'},
    {"keypath", required_argument, NULL, 'm'},
    {"command", required_argument, NULL, 'c'},
    {"testnet", no_argument, NULL, 't'},
    {"regtest", no_argument, NULL, 'r'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
};

static void print_version() {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage() {
    print_version();
    printf("Usage: bitcointool (-p <privatekey>) (-t[--testnet]) (-r[--regtest]) -c <command>\n");
    printf("Available commands: pubfrompriv, addrfrompub, genkey\n");
    printf("\nExamples: \n");
    printf("Generate a testnet privatekey in WIF/HEX format:\n");
    printf("> bitcointool -c gen --testnet\n\n");
}

static bool showError(const char *er)
{
    printf("Error: %s\n", er);
    return 0;
}

int main(int argc, char *argv[])
{
    int long_index =0;
    int opt= 0;
    char *cmd = 0;
    char *keypath = 0;


    /* get arguments */
    while ((opt = getopt_long_only(argc, argv,"p:k:m:c:trv", long_options, &long_index )) != -1) {
        switch (opt) {
            // case 'p' :
            //     pkey = optarg;
            //     if (strlen(pkey) < 50)
            //         return showError("Private key must be WIF encoded");
            //     break;
            // case 'c' : cmd = optarg;
            //     break;
            // case 'm' : keypath = optarg;
            //     break;
            // case 'k' : pubkey = optarg;
            //     break;
            // case 't' :
            //     chain = &btc_chain_test;
            //     break;
            // case 'r' :
            //     chain = &btc_chain_regt;
            //     break;
            case 'v' :
                print_version();
                exit(EXIT_SUCCESS);
                break;
            default: print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (!cmd)
    {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* start ECC context */
    btc_ecc_start();

    btc_ecc_stop();

    return 0;
}
