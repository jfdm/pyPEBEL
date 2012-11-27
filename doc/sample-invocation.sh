#!/bin/bash
## ------------------------------------------------------ [ Sample Innvocation ]
#
# List of sample commands to show how the scripts within pyPEBEL can be used.
#

## --------------------------------------------------------------- [ Data File ]
echo "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad
minim veniam, quis nostrud exercitation ullamco laboris nisi ut
aliquip ex ea commodo consequat. Duis aute irure dolor in
reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
culpa qui officia deserunt mollit anim id est laborum." > myfile.data

## ------------------------------------------------------------------ [ CP-ABE ]

## ------------------------------------------------------------------- [ Setup ]
python pebel/scripts/pyCPABE-setup.py

## ------------------------------------------------------------------ [ KeyGen ]
python pebel/scripts/pyCPABE-keygen.py \
    --mpk cp.mpk \
    --msk cp.msk \
    --dkey right.cpabe.dkey \
    one two three four

python pebel/scripts/pyCPABE-keygen.py \
    --mpk cp.mpk \
    --msk cp.msk \
    --dkey wrong.cpabe.dkey \
    five six seven eight

## ----------------------------------------------------------------- [ Encrypt ]
python pebel/scripts/pyCPABE-encrypt.py \
    --mpk cp.mpk \
    --ptxt myfile.data \
    '(ONE and TWO) or THREE'

## ----------------------------------------------------------------- [ Decrypt ]
python pebel/scripts/pyCPABE-decrypt.py \
    --mpk cp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey right.cpabe.dkey

python pebel/scripts/pyCPABE-decrypt.py \
    --mpk cp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey wrong.cpabe.dkey

## ------------------------------------------------------------------ [ KP-ABE ]

## ------------------------------------------------------------------- [ Setup ]
python pebel/scripts/pyKPABE-setup.py
## ------------------------------------------------------------------ [ KeyGen ]
python pebel/scripts/pyKPABE-keygen.py \
    --mpk kp.mpk \
    --msk kp.msk \
    --dkey right.kpabe.dkey \
    '(one and two) or (three and four)'

python pebel/scripts/pyKPABE-keygen.py \
    --mpk kp.mpk \
    --msk kp.msk \
    --dkey wrong.kpabe.dkey \
    '(five and six) or (seven and eight)'

## ----------------------------------------------------------------- [ Encrypt ]
python pebel/scripts/pyKPABE-encrypt.py \
    --mpk kp.mpk \
    --ptxt myfile.data \
    'one two five eight'

## ----------------------------------------------------------------- [ Decrypt ]
python pebel/scripts/pyKPABE-decrypt.py \
    --mpk kp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey right.kpabe.dkey

python pebel/scripts/pyKPABE-decrypt.py \
    --mpk kp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey wrong.kpabe.dkey

## ----------------------------------------------------------------- [ Cleanup ]
rm -i *.dkey *.mpk *.msk *.cpabe *.kpabe
