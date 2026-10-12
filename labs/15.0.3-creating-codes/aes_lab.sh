#!/usr/bin/env bash
cd "$(dirname "$0")"
mkdir -p output

KEY="netsec"
enc() { printf '%s' "$1" | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -base64 -A -pass pass:"$KEY"; }

{
for msg in \
  "The weather is nice today, let's go for a walk in the park." \
  "Don't forget to buy milk and bread on the way home."
do
  echo "$msg"
  enc "$msg"; echo
  echo
done
} | tee output/lab_run.txt
