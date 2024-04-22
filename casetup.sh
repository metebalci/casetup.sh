#!/bin/bash
#
# SPDX-FileCopyrightText: 2024 Mete Balci
# 
# SPDX-License-Identifier: Apache-2.0
# 
# Copyright (c) 2024 Mete Balci
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

function debug
{
  if [ "${CASETUP_DEBUG}" == "1" ]
  then
    echo "DEBUG: $1"
  fi
}

function error
{
  echo "ERROR: $1"
  exit 1
}

if [ -z "${CASETUP_CONF}" ]
then
  error "please set CASETUP_CONF environment variable to the casetup configuration file"
fi

debug "CASETUP_CONF=${CASETUP_CONF}"

source "${CASETUP_CONF}"

debug "PKCS11_TOOL_ARGS=$PKCS11_TOOL_ARGS"
debug "OPENSSL_ARGS=$OPENSSL_ARGS"

debug "ROOT_DIR=$ROOT_DIR"
debug "INTERMEDIATE_DIR=$INTERMEDIATE_DIR"

debug "TOKEN_SERIAL=$TOKEN_SERIAL"
debug "ROOT_KEY_TYPE=$ROOT_KEY_TYPE"
debug "INTERMEDIATE_KEY_TYPE=$INTERMEDIATE_KEY_TYPE"
debug "USER_KEY_TYPE=$USER_KEY_TYPE"

debug "ROOT_CERT_DAYS=$ROOT_CERT_DAYS"
debug "INTERMEDIATE_CERT_DAYS=$INTERMEDIATE_CERT_DAYS"
debug "USER_CERT_DAYS=$USER_CERT_DAYS"

#if [ "${ROOT_KEY_TYPE:0:3}" == "rsa" ]
#then
#  ROOT_KEY_LENGTH=${ROOT_KEY_TYPE:4}
#else
#  ROOT_KEY_LENGTH=0
#fi
#
#if [ "${INTERMEDIATE_KEY_TYPE:0:3}" == "rsa" ]
#then
#  INTERMEDIATE_KEY_LENGTH=${INTERMEDIATE_KEY_TYPE:4}
#else
#  INTERMEDIATE_KEY_LENGTH=0
#fi
#
#debug "ROOT_KEY_LENGTH=$ROOT_KEY_LENGTH"
#debug "INTERMEDIATE_KEY_LENGTH=$INTERMEDIATE_KEY_LENGTH"

# read .token_pin if it exists
# this is not very secure but simplifies automation
if [ ! -z "$CASETUP_TOKEN_PIN" ]
then
  mode=`stat -c %a "$CASETUP_TOKEN_PIN"`
  if [ "$mode" -ne "400" ]
  then
    error "please set TOKEN_PIN file permissions to read only by owner (400)"
  fi
  debug "CASETUP_TOKEN_PIN=$CASETUP_TOKEN_PIN"
  TOKEN_PIN=`cat "$CASETUP_TOKEN_PIN"`
else
  TOKEN_PIN=""
fi

# KPS file paths
ROOT_KPS_FILE="${ROOT_DIR}/.kps"
INTERMEDIATE_KPS_FILE="${INTERMEDIATE_DIR}/.kps"
# id, label and (private) token url of keypairs
ROOT_KP_ID=
ROOT_KP_LABEL=
ROOT_KP_URL=
INTERMEDIATE_KP_ID=
INTERMEDIATE_KP_LABEL=
INTERMEDIATE_KP_URL=
# ---------------------------------------------------------------------

# append PIN to pkcs11-tool and openssl args
if [ ! -z "$TOKEN_PIN" ]
then
  PKCS11_TOOL_ARGS="${PKCS11_TOOL_ARGS} --pin ${TOKEN_PIN}"
  OPENSSL_ARGS="${OPENSSL_ARGS} --passin pass:${TOKEN_PIN}"
fi

if [ ! -z "$DEBUG" ]
then
  DEBUG=0
fi


function info
{
  echo "INFO: $1"
}

function check_tools
{
  which pkcs11-tool > /dev/null 2>&1 || error "requires pkcs11-tool"
  which p11tool > /dev/null 2>&1 || error "requires p11tool"
  which openssl > /dev/null 2>&1 || error "requires openssl"
}

function read_kps
{
  if [ -f "$ROOT_KPS_FILE" ]
  then
    ROOT_KP_ID=`cut -d':' -f1 $ROOT_KPS_FILE`
    ROOT_KP_LABEL=`cut -d':' -f2 $ROOT_KPS_FILE`
    ROOT_KP_URL=`cut -d':' -f3- $ROOT_KPS_FILE`
  fi

  if [ -f "$INTERMEDIATE_KPS_FILE" ]
  then
    INTERMEDIATE_KP_ID=`cut -d':' -f1 $ROOT_KPS_FILE`
    INTERMEDIATE_KP_LABEL=`cut -d':' -f2 $ROOT_KPS_FILE`
    INTERMEDIATE_KP_URL=`cut -d':' -f3- $ROOT_KPS_FILE`
  fi
}

function create_kp
{
  LABEL="$1"
  KEYTYPE="$2"
  DIR="$3"
  debug "create_kp LABEL=\"$LABEL\" KEYTYPE=\"$KEYTYPE\" DIR=\"$DIR\""

  KPSFILE="${DIR}/.kps"

  if [ -f $KPSFILE ]
  then
    error "${KPSFILE} exists"
  fi

  echo "creating \"$LABEL\" keypair..."

  pkcs11-tool $PKCS11_TOOL_ARGS -l --keypairgen --key-type "$KEYTYPE" --label "$LABEL"

  if [ $? -ne 0 ]
  then
    error "cannot create \"$LABEL\" keypair"
  else
    # read the ID of generated key
    ID=`pkcs11-tool $PKCS11_TOOL_ARGS -O | grep -A 1 "[[:blank:]]\+label:[[:blank:]]\+$LABEL" | tail -n 1 | cut -d':' -f2 | tr -d ' '`
    echo "id=$ID"

    info "$KEYTYPE keypair \"$LABEL\" created with id=$ID at $PRIVKEY_URL"

    ID_WITH_PERCENTS="%`echo $ID | fold -w2 | paste -sd'%' -`"
    ID_WITH_PERCENTS=${ID_WITH_PERCENTS^^}
    debug "ID_WITH_PERCENTS=$ID_WITH_PERCENTS"

    PRIVKEY_URL=`p11tool --list-all "$TOKEN_URL" | grep "type=public" | grep "$ID_WITH_PERCENTS" | cut -d':' -f2- | tr -d ' ' | sed 's/type=public$/type=private/'`
    debug "PRIVKEY_URL=$PRIVKEY_URL"

    info "recreating the directories"
    rm -rf $DIR
    mkdir -p $DIR $DIR/certs $DIR/crl $DIR/csr $DIR/newcerts
    touch $DIR/index.txt 

    # add this entry to kps
    echo "$ID:$LABEL:$PRIVKEY_URL" >> $KPSFILE
    info "directories and .kps created."

  fi
}

function create_root_cert
{
  CN="$1"
  debug "create_root_cert CN=\"$CN\""

  read_kps

  if [ -f "$ROOT_DIR/certs/root.cert.pem" ]
  then
    error "there is already a $ROOT_DIR/certs/root.cert.pem"
  fi
  
  OPENSSL_CONF=$(mktemp -t casetup-XXXXXXXXXX)

cat > $OPENSSL_CONF << EOF
[req]
default_md          = $DIGEST
string_mask         = utf8only
x509_extensions     = v3_ca
prompt              = no
distinguished_name  = req_distinguished_name

[req_distinguished_name]
C   = $COUNTRY
O   = $ORGANIZATION
CN  = $CN

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
# same as ISRG Root X1 (pathlen=unlimited)
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
EOF

  debug "openssl.conf=$OPENSSL_CONF"

  echo "creating self signed root cert..."

  openssl req \
    $OPENSSL_ARGS \
    -config $OPENSSL_CONF \
    -engine pkcs11 -keyform engine \
    -key $ROOT_KP_ID \
    -new -x509 -days $ROOT_CERT_DAYS \
    -out $ROOT_DIR/certs/root.cert.pem

  if [ $? -eq 0 ]
  then
    openssl x509 -in $ROOT_DIR/certs/root.cert.pem -noout -text
  else
    error "cannot create root cert"
  fi

  echo "root cert created."
}

function create_intermediate_cert
{
  CN="$1"
  debug "create_intermediate_cert CN=\"$CN\""

  read_kps

  if [ -f "$INTERMEDIATE_DIR/certs/intermediate.cert.pem" ]
  then
    error "there is already a $INTERMEDIATE_DIR/certs/intermediate.cert.pem"
  fi

  OPENSSL_CONF=$(mktemp -t casetup-XXXXXXXXXX)

cat > $OPENSSL_CONF << EOF
[req]
default_md          = $DIGEST
string_mask         = utf8only
req_extensions      = v3_ca
prompt              = no
distinguished_name  = req_distinguished_name

[req_distinguished_name]
C   = $COUNTRY
O   = $ORGANIZATION
CN  = $CN

[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF

  debug "openssl.conf=$OPENSSL_CONF"

  echo "creating intermediate csr..."

  openssl req \
    $OPENSSL_ARGS \
    -config $OPENSSL_CONF \
    -engine pkcs11 -keyform engine \
    -key $INTERMEDIATE_KP_ID \
    -new \
    -out $INTERMEDIATE_DIR/csr/intermediate.csr

  if [ $? -eq 0 ]
  then
    openssl req -in $INTERMEDIATE_DIR/csr/intermediate.csr -noout -text
  else
    error "cannot create intermediate csr"
  fi

  echo "intermediate csr created."
  
  OPENSSL_CONF=$(mktemp -t casetup-XXXXXXXXXX)

cat > $OPENSSL_CONF << EOF
[ca]
default_ca = CA_default

[CA_default]
dir               = $ROOT_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial

private_key       = $ROOT_KP_URL
certificate       = \$dir/certs/root.cert.pem

default_md        = $DIGEST
default_days      = 1825

name_opt          = ca_default
cert_opt          = ca_default
preserve          = no
policy            = policy_loose
# all extensions mainly come from the CSR
# here only authorityKeyIdentifier is added
x509_extensions   = v3_intermediate_ca
copy_extensions   = copyall

[policy_loose]
countryName                     = optional
stateOrProvinceName             = optional
localityName                    = optional
organizationName                = optional
organizationalUnitName          = optional
commonName                      = optional
emailAddress                    = optional

[v3_intermediate_ca]
authorityKeyIdentifier = keyid:always,issuer
EOF

  debug "openssl.conf=$OPENSSL_CONF"

  echo "signing intermediate cert..."

  openssl ca \
    $OPENSSL_ARGS \
    -batch \
    -config $OPENSSL_CONF \
    -engine pkcs11 -keyform engine \
    -days $INTERMEDIATE_CERT_DAYS \
    -notext -create_serial \
    -in $INTERMEDIATE_DIR/csr/intermediate.csr \
    -out $INTERMEDIATE_DIR/certs/intermediate.cert.pem

  if [ $? -eq 0 ]
  then
    openssl x509 -in $INTERMEDIATE_DIR/certs/intermediate.cert.pem -noout -text
  else
    error "cannot create intermediate cert"
  fi

  echo "intermediate cert created."

  openssl verify \
    -CAfile $ROOT_DIR/certs/root.cert.pem \
    $INTERMEDIATE_DIR/certs/intermediate.cert.pem

  if [ $? -ne 0 ]
  then
    error "cannot verify the intermediate cert against root cert ?!"
  fi

  cat $INTERMEDIATE_DIR/certs/intermediate.cert.pem \
    $ROOT_DIR/certs/root.cert.pem > $INTERMEDIATE_DIR/certs/chain.cert.pem
}

function create_user_csr
{
  CN="$1"
  PREFIX=$2
  debug "create_user_csr CN=\"$CN\" PREFIX=\"$PREFIX\""

  KEY_FILE="$PREFIX.key.pem"
  CSR_FILE="$PREFIX.csr"

  OPENSSL_CONF=$(mktemp -t casetup-XXXXXXXXXX)

  debug "openssl.conf=$OPENSSL_CONF"

  cat << EOF > "$OPENSSL_CONF"
[req]
default_md          = $DIGEST
string_mask         = utf8only
req_extensions      = v3_ext
prompt              = no
distinguished_name  = req_distinguished_name
encrypt_key         = no

[req_distinguished_name]
C   = $COUNTRY
O   = $ORGANIZATION
CN  = $CN

[v3_ext]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
EOF

# for some reason neither ec:secp256r1 nor ec:prime256v1 is supported in OpenSSL 3.0.2
# but ecparam for secp256r1 can be generated and used

if [ "${USER_KEY_TYPE:0:2}" == "EC" ]
then

  ecparam=$(mktemp -t casetup-XXXXXXXXXX)
  openssl ecparam -name "${USER_KEY_TYPE:3}" -out "$ecparam"

  openssl req \
    -config "$OPENSSL_CONF" \
    -newkey "param:$ecparam" \
    -keyout $KEY_FILE \
    -new -out $CSR_FILE

else

  openssl req \
    -config "$OPENSSL_CONF" \
    -newkey "$USER_KEY_TYPE" \
    -keyout $KEY_FILE \
    -new -out $CSR_FILE

fi

  if [ $? -eq 0 ]
  then
    openssl req -in "$CSR_FILE" -noout -text
  else
    error "cannot create user csr"
  fi

  echo "user csr created."
}

function sign_user_csr
{
  PREFIX=$1
  debug "sign_user_csr PREFIX=$PREFIX"

  CSR_FILE="$PREFIX.csr"
  CERT_FILE="$PREFIX.cert.pem"

  read_kps
  
  OPENSSL_CONF=$(mktemp -t casetup-XXXXXXXXXX)

cat > $OPENSSL_CONF << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $INTERMEDIATE_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial

private_key       = $INTERMEDIATE_KP_URL
certificate       = \$dir/certs/intermediate.cert.pem

default_md        = $DIGEST

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ server_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
EOF

  debug "openssl.conf=$OPENSSL_CONF"

  echo "signing csr..."

  openssl ca \
    $OPENSSL_ARGS \
    -batch \
    -config $OPENSSL_CONF \
    -engine pkcs11 -keyform engine \
    -notext -create_serial \
    -in "$CSR_FILE" \
    -out "$CERT_FILE"

  if [ $? -eq 0 ]
  then
    openssl x509 -in "$CERT_FILE" -noout -text
  else
    error "cannot sign csr"
  fi

  echo "csr signed, cert created."

  openssl verify \
    -CAfile "$INTERMEDIATE_DIR/certs/chain.cert.pem" \
    "$CERT_FILE"

  if [ $? -ne 0 ]
  then
    error "cannot verify the new cert against chain ?!"
  fi

}

function delete_kp
{
  DIR="$1"
  debug "delete_kp DIR=\"$DIR\""

  KPSFILE="${DIR}/.kps"

  if [ ! -f $KPSFILE ]
  then
    error "no $KPSFILE"
  fi

  ID=`cut -d':' -f1 "$KPSFILE"`
  LABEL=`cut -d':' -f2 "$KPSFILE"`

  if [ -z "$ID" ] || [ -z "$LABEL" ]
  then
    error "wrong values in $KPSFILE"
  fi

  echo "deleting pubkey id=$ID, label=\"$LABEL\"..."

  pkcs11-tool $PKCS11_TOOL_ARGS --delete-object --id "$ID" --type pubkey
  if [ $? -eq 0 ]
  then
    info "$LABEL pubkey is deleted."
  else
    info "$LABEL pubkey is NOT deleted. (maybe no such key)"
  fi

  echo "deleting privkey, id=$ID, label=\"$LABEL\"..."

  pkcs11-tool $PKCS11_TOOL_ARGS -l --delete-object --id "$ID" --type privkey
  if [ $? -eq 0 ]
  then
    info "$LABEL privkey is deleted."
  else
    info "$LABEL privkey is NOT deleted. (maybe no such key)"
  fi

  # remove directory
  rm -rf $DIR
}

function display_status
{
  read_kps

  echo "casetup records:"

  if [ ! -z "$ROOT_KP_ID" ] || [ ! -z "$ROOT_KP_LABEL" ]
  then
    echo "root kp: ${ROOT_KP_ID} ${ROOT_KP_LABEL}"
  fi

  if [ ! -z $INTERMEDIATE_KP_ID ] || [ ! -z "$INTERMEDIATE_KP_LABEL" ]
  then
    echo "root kp: $INTERMEDIATE_KP_ID $INTERMEDIATE_KP_LABEL"
  fi

  echo "pkcs11 objects:"

  pkcs11-tool $PKCS11_TOOL_ARGS -l -O
}

function clean
{
  if [ -f "$ROOT_KPS_FILE" ]
  then
    delete_kp $ROOT_DIR
  fi

  if [ -f "$INTERMEDIATE_KPS_FILE" ]
  then
    delete_kp $INTERMEDIATE_DIR
  fi

  rm -rf $ROOT_DIR
  rm -rf $INTERMEDIATE_DIR
}

function delete_pubkeys
{
  for ID in $(pkcs11-tool $PKCS11_TOOL_ARGS -l -O --type pubkey | grep "ID:" | cut -d':' -f2 | tr -d ' ')
  do
    echo "deleting pubkey $ID"
    pkcs11-tool $PKCS11_TOOL_ARGS -l --delete-object --id $ID --type pubkey
  done
}

function delete_privkeys
{

  for ID in $(pkcs11-tool $PKCS11_TOOL_ARGS -l -O --type privkey | grep "ID:" | cut -d':' -f2 | tr -d ' ')
  do
    echo "deleting privkey $ID"
    pkcs11-tool $PKCS11_TOOL_ARGS -l --delete-object --id $ID --type privkey
  done
}

function usage
{
  echo ""
  echo "casetup.sh is a collection of CA setup utilities using pkcs11-tool, p11tool and openssl."
  echo "See https://github.com/metebalci/casetup.sh for more information."
  echo ""
  echo "Usage: casetup.sh COMMAND OPTIONS?"
  echo ""
  echo "Commands:"
  echo ""
  echo "- create_root_kp <LABEL>: create the root keypair with LABEL"
  echo "- delete_root_kp: delete the root keypair"
  echo ""
  echo "- create_intermediate_kp <LABEL>: create the intermediate keypair with LABEL"
  echo "- delete_intermediate_kp: delete the intermediate keypair"
  echo ""
  echo "- create_root_cert <CN>: self sign the root keypair"
  echo "- create_intermediate_cert <CN>: create a CSR for the intermediate keypair and sign it with the root cert"
  echo ""
  echo "- create_user_csr <CN> <PREFIX>: create a user keypair (PREFIX.key.pem) and its CSR (PREFIX.csr)"
  echo "- sign_user_csr <PREFIX>: sign a user CSR (PREFIX.csr) using the intermediate cert and generate its certificate (PREFIX.cert.pem)"
  echo ""
  echo "- status: display current status"
  echo "- clean: clean all setup (WARNING !!! DELETES EVERYTHING CREATED WITH casetup.sh)"
  echo "- delete_keys: delete all private and public keys in the token (!!! WARNING !!!)"
  echo ""
  exit 1
}

check_tools

if [ "$#" -eq 0 ]
then
  usage
fi

COMMAND=$1

debug "COMMAND=$COMMAND"

case "$COMMAND" in

  create_root_kp)
    if [ "$#" -ne 2 ]
    then
      error "usage: $COMMAND <LABEL>"
    fi
    LABEL="$2"
    create_kp "$LABEL" "$ROOT_KEY_TYPE" "$ROOT_DIR"
    ;;

  delete_root_kp)
    delete_kp $ROOT_KPS_DIR
    ;;

  create_intermediate_kp)
    if [ "$#" -ne 2 ]
    then
      error "usage: $COMMAND <LABEL>"
    fi
    LABEL="$2"
    create_kp "$LABEL" "$INTERMEDIATE_KEY_TYPE" "$INTERMEDIATE_DIR"
    ;;

  delete_intermediate_kp)
    delete_kp $INTERMEDIATE_KPS_DIR
    ;;

  create_root_cert)
    if [ "$#" -ne 2 ]
    then
      error "usage: $COMMAND <CN>"
    fi
    CN="$2"
    create_root_cert "$CN"
    ;;

  create_intermediate_cert)
    if [ "$#" -ne 2 ]
    then
      error "usage: $COMMAND <CN>"
    fi
    CN="$2"
    create_intermediate_cert "$CN"
    ;;

  create_user_csr)
    if [ "$#" -ne 3 ]
    then
      error "usage: $COMMAND <CN> <PREFIX>"
    fi
    CN="$2"
    PREFIX="$3"
    create_user_csr "$CN" "$PREFIX"
    ;;

  sign_user_csr)
    if [ "$#" -ne 2 ]
    then
      error "usage: $COMMAND <PREFIX>"
    fi
    PREFIX="$2"
    sign_user_csr "$PREFIX"
    ;;
  
  status)
    display_status
    ;;

  clean)
    clean
    ;;

  delete_keys)
    delete_pubkeys
    delete_privkeys
    ;;

  *)
    usage
    ;;

esac

exit 0
