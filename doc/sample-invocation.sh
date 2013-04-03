#!/bin/bash
## ------------------------------------------------------ [ Sample Innvocation ]
#
# List of sample commands to show how the scripts within pyPEBEL can be used.
#
# I am going to assume that you have installed the module.
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
pyCPABE-setup.py

## ------------------------------------------------------------------ [ KeyGen ]
pyCPABE-keygen.py \
    --mpk cp.mpk \
    --msk cp.msk \
    --dkey right.cpabe.dkey \
    one two three four

pyCPABE-keygen.py \
    --mpk cp.mpk \
    --msk cp.msk \
    --dkey wrong.cpabe.dkey \
    five six seven eight

## ----------------------------------------------------------------- [ Encrypt ]
pyCPABE-encrypt.py \
    --mpk cp.mpk \
    --ptxt myfile.data \
    '(ONE and TWO) or THREE'

## ----------------------------------------------------------------- [ Decrypt ]
pyCPABE-decrypt.py \
    --mpk cp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey right.cpabe.dkey

pyCPABE-decrypt.py \
    --mpk cp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey wrong.cpabe.dkey

## ------------------------------------------------------------------ [ KP-ABE ]

## ------------------------------------------------------------------- [ Setup ]
pyKPABE-setup.py
## ------------------------------------------------------------------ [ KeyGen ]
pyKPABE-keygen.py \
    --mpk kp.mpk \
    --msk kp.msk \
    --dkey right.kpabe.dkey \
    '(one and two) or (three and four)'

pyKPABE-keygen.py \
    --mpk kp.mpk \
    --msk kp.msk \
    --dkey wrong.kpabe.dkey \
    '(five and six) or (seven and eight)'

## ----------------------------------------------------------------- [ Encrypt ]
pyKPABE-encrypt.py \
    --mpk kp.mpk \
    --ptxt myfile.data \
    'one two five eight'

## ----------------------------------------------------------------- [ Decrypt ]
pyKPABE-decrypt.py \
    --mpk kp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey right.kpabe.dkey

pyKPABE-decrypt.py \
    --mpk kp.mpk \
    --ctxt myfile.data.cpabe \
    --dkey wrong.kpabe.dkey

## ----------------------------------------------------------------- [ Cleanup ]
rm -i *.dkey *.mpk *.msk *.cpabe *.kpabe
