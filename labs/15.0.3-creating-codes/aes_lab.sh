#!/usr/bin/env bash
# Lab 15.0.3 - Creating Codes, reproduced offline with OpenSSL.
# AES-256-CBC, key derived from the password with PBKDF2, output in base64
# (same idea as aesencryption.net: plaintext + secret key -> base64 ciphertext).
set -u
cd "$(dirname "$0")"
mkdir -p output

KEY="netsec"
WRONG_KEY="netsec1"
enc() { printf '%s' "$1" | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -base64 -A -pass pass:"$2"; }
dec() { printf '%s\n' "$1" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -base64 -A -pass pass:"$2" 2>&1; }

MSG_A="LockBit affiliates use Citrix Bleed (CVE-2023-4966) for initial access. Patch NetScaler today."
MSG_B="Meet at the SOC at 10:00, bring the MISP export."

{
echo "== Part 2: Partner A encrypts a message =="
echo "Plaintext : $MSG_A"
echo "Secret key: $KEY"
CT_A=$(enc "$MSG_A" "$KEY")
echo "Ciphertext (base64): $CT_A"
echo
echo "== Part 2: Partner B encrypts a message =="
echo "Plaintext : $MSG_B"
echo "Secret key: $KEY"
CT_B=$(enc "$MSG_B" "$KEY")
echo "Ciphertext (base64): $CT_B"
echo
echo "== Same plaintext encrypted twice (random salt/IV) =="
echo "1: $(enc "$MSG_B" "$KEY")"
echo "2: $(enc "$MSG_B" "$KEY")"
echo
echo "== Part 3: Partner B decrypts A's ciphertext with the pre-shared key =="
echo "Result: $(dec "$CT_A" "$KEY")"
echo
echo "== Part 3: Partner A decrypts B's ciphertext with the pre-shared key =="
echo "Result: $(dec "$CT_B" "$KEY")"
echo
echo "== Question: decrypting with a wrong key ($WRONG_KEY) =="
echo "OpenSSL says:"
dec "$CT_A" "$WRONG_KEY" | head -2
echo
echo "== Wrong key, raw output without padding check (-nopad) =="
printf '%s\n' "$CT_A" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -base64 -A -nopad -pass pass:"$WRONG_KEY" | od -An -tx1 | head -4
echo "As text: $(printf '%s\n' "$CT_A" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -base64 -A -nopad -pass pass:"$WRONG_KEY" | head -c 48 | tr -c '[:print:]' '?')"
} | tee output/lab_run.txt
