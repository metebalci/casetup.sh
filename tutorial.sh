#!/bin/bash

set -e

if [ "$#" -ne "1" ]
then
  echo "usage: ./tutorial.sh rsa|ecdsa"
  exit 1
fi

mode=$1

ca_dir=./tutorial
casetup_conf=./tutorial/casetup.conf

cat << EOF > "$casetup_conf"
# args
PKCS11_TOOL_ARGS="--slot 0"
OPENSSL_ARGS=""
# dirs
ROOT_DIR=$ca_dir/ca_root
INTERMEDIATE_DIR=$ca_dir/ca_intermediate
# token selection
TOKEN_SERIAL=DENK0301580
EOF

if [ "$mode" == "rsa" ]
then
cat << EOF >> "$casetup_conf"
# key types
ROOT_KEY_TYPE=rsa:4096
INTERMEDIATE_KEY_TYPE=rsa:2048
USER_KEY_TYPE=rsa:2048
DIGEST=sha256
EOF
elif [ "$mode" == "ecdsa" ]
then
cat << EOF >> "$casetup_conf"
# key types
ROOT_KEY_TYPE=EC:secp384r1
INTERMEDIATE_KEY_TYPE=EC:secp384r1
USER_KEY_TYPE=EC:secp256r1
DIGEST=sha384
EOF
else
echo "usage: ./tutorial.sh rsa|ecdsa"
exit 1
fi

cat << EOF >> "$casetup_conf"
# cert
COUNTRY=CH
ORGANIZATION=tutorial
ROOT_CERT_DAYS=7300
INTERMEDIATE_CERT_DAYS=1825
USER_CERT_DAYS=365
EOF

echo "ca_dir=$ca_dir"
echo "casetup_conf=$casetup_conf"

export CASETUP_CONF="$casetup_conf"
export CASETUP_TOKEN_PIN=.token_pin

./casetup.sh clean
./casetup.sh create_root_kp "tutorial root"
./casetup.sh create_root_cert "tutorial root"
./casetup.sh create_intermediate_kp "tutorial intermediate"
./casetup.sh create_intermediate_cert "tutorial intermediate"
rm -rf "$ca_dir/user.key.pem" "$ca_dir/user.csr" "$ca_dir/user.cert.pem"
./casetup.sh create_user_csr "user" "$ca_dir/user"
./casetup.sh sign_user_csr "$ca_dir/user"
./casetup.sh status

