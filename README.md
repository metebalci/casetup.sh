*** Warning: casetup.sh includes commands that removes files, directories and keys in a PKCS11 token. Use with caution, it is not tested for production use. ***

# casetup.sh

`casetup.sh` is a bash script to create and manage a simple Certificate Authority (CA) using a cryptographic token. It uses `openssl`, `pkcs11-tool` and `p11tool`. The token is most probably a hardware token and it supports the PKCS11 interface, however it can also be a software token as long as it can be accessed through PKCS11 (Cryptoki) API.

In a typical CA setup, there is a root and an intermediate certificate. The root certificate has a longer lifetime (e.g. 20 years) and it is only used for signing the intermediate certificates with a shorter lifetime (e.g. 5 years). All user generated certificates are then signed with the intermediate certificate. `casetup.sh` exactly mimics this setup.

The distinguished name (consisting only C, O and CN) and extensions of the certificates are similar to Lets Encrypt certificates, however they can be (and might have to be) modified according to individual needs.

I am using `casetup.sh` together with a [Nitrokey HSM 2](https://shop.nitrokey.com/shop/nkhs2-nitrokey-hsm-2-7) hardware token on Ubuntu 22.04.

`casetup.sh` is basically a single shell script performing all the operations described in [Creating a Certificate Authority by Nitrokey for Nitrokey HSM](https://docs.nitrokey.com/hsm/linux/certificate-authority). Both this page and the page [OpenSSL Certificate Authority by Jamie Nguyen](https://jamielinux.com/docs/openssl-certificate-authority/index.html) describes all the steps which require manual typing and some copy-and-paste. `casetup.sh` removes the need for manual intervention.

# Usage

## Configuration

`casetup.sh` requires a single configuration file whose path should be defined in an environment variable called `CASETUP_CONF`.

This file contains the following:

- `PKCS11_TOOL_ARGS`: extra arguments to supply to pkcs11-tool, for example `--slot 0`
- `OPENSSL_ARGS`: extra arguments to supply to openssl
- `ROOT_DIR`: directory where the root related CA data will be stored
- `INTERMEDIATE_DIR`: directory where the intermediate related CA data will be stored
- `TOKEN_SERIAL`: the serial number of the token to be used
- `ROOT_KEY_TYPE`: type of root keypair stored in the token
- `INTERMEDIATE_KEY_TYPE`: type of intermediate keypair stored in the token
- `USER_KEY_TYPE`: type of user keypair stored in the computer (not in the token)
- `DIGEST`: message digest algorithm to use in certificates
- `COUNTRY`: country (C) value of the certificate (used in root, intermediate and user certificates)
- `ORGANIZATION`: organization (O) value of the certificate (used in root, intermediate and user certificates)
- `ROOT_CERT_DAYS`: valid lifetime of root certificate (e.g. 7300 for 20 years)
- `INTERMEDIATE_CERT_DAYS`: valid lifetime of intermediate certificate (e.g. 1825 days for 5 years)
- `USER_CERT_DAYS`: valid lifetime of user certificates (e.g. 365 days for 1 year)

There are basically two cryptographic methods when using a CA; RSA and ECDSA (Elliptic Curve Digital Signature Algorithm).

Typical values for `KEY_TYPE` are:

- rsa:2048, rsa:3072 and rsa:4096. Typically, 4096 is used for the root certificate, 2048 is used for the intermediate and user certificates. After 2031 and beyond, rsa:2048 is not recommended.

- EC:prime256v1 (another name for secp256p1) and EC:secp384r1. Typically, 384 is used for the root and intermediate certificates, and 256 is used for the user certificates. Both algorithms are OK to use after 2031 and beyond.

EC algorithms are considered to have following equivalance: (source: [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf))

- EC:prime256v1 is considered to be equivalent to 3072 bit RSA (or DSA) scheme.
- EC:secp384r1 is considered to be equivalent to 7680 bit RSA (or DSA) scheme.

`DIGEST` can be sha256 and sha384 (and even sha512). sha1 is not used anymore.

Both RSA and ECDSA can be used with sha256 and sha384. Typically sha256 is used with RSA (2048-4096) and sha384 is used with ECDSA (both with prime256v1 and secp384r1).

Keep in mind that the root and intermediate keypairs are created on the PKCS11 token. Thus, the token has to support the provided `KEY_TYPE` and `DIGEST` values. `pkcs11-tool -M` lists the supported mechanisms by the token, and the vendor should provide a detailed documentation.

## Debug Logging

The level of logging is increased if `CASETUP_DEBUG` environment variable is set to "1".

## Token PIN

Typically, a token is protected with a PIN which is required to use a private key. This provides security but also prevents automation. If you want, the PIN can be stored into a file and the file path can be set to an environment variable called `CASETUP_TOKEN_PIN`,  then it will be used by `casetup.sh`. The file should be readable only by the owner, thus it should have 400 permission.

## Runtime

When `casetup.sh` is used to create keypairs, a file named `.kps` is created under `ROOT_DIR` and `INTERMEDIATE_DIR`. This file contains a single line for the ID, label and token URL of the keypair stored in the PKCS11 token. This file should not be deleted for `casetup.sh` to work.

## Temporary Files

When `casetup.sh` is used, a few temporary files, for openssl configuration, are created under the system temp directory (with `mktemp` command). They are all prefixed with `casetup-`.

# Tutorial

A tutorial `tutorial.sh` is provided as an example. It requires a single argument, either rsa or ecdsa. `tutorial.sh` generates a conf file according to the argument, and then performs a clean first. Then, a full CA setup is made. Finally, a user csr and certificate is generated.

`tutorial.sh` creates and uses `./tutorial` directory and `./tutorial/casetup.conf` configuration file.

# Implementation Notes

- `p11tool` is used to find the URL of keys in the token. The URL of private keys are needed, however this requires the token PIN and `p11tool` does not accept token PIN in other ways for automation. Therefore, it is assumed that ID/URL of public and private keys are same other than the type parameter. Then, `p11tool` is used to list public keys (which requires no PIN) and then the type parameter is changed from `type=public` to `type=private`. This method works with Nitrokey HSM 2 but it might not work with other tokens.

- OpenSSL 3.0.2 on Ubuntu 22.04 does not support using `openssl req -newkey` with `ec:secp256r1` or `ec:prime256v1`. However, it supports generating ecparam and using it with req. This method is used in `casetup.sh`. Also, secp256r1 is also called prime256v1, they are the same curves.
