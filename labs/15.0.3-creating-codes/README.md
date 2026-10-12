# Lab 15.0.3 - Creating Codes

Cisco NetAcad lab: encrypt a message with AES using a shared secret key, send the ciphertext to a lab partner, decrypt the partner's ciphertext, and see what happens with a wrong key.

## How it was done

The lab suggests an online tool (aesencryption.net). I reproduced the same steps offline with OpenSSL so the run can be repeated and checked: [`aes_lab.sh`](aes_lab.sh), full output in [`output/lab_run.txt`](output/lab_run.txt).

- Algorithm: AES-256-CBC (symmetric)
- Secret key (password): `netsec`, the same as in the lab example
- Key derivation: PBKDF2, 100000 iterations, random salt
- Output: base64, like the "Result of encryption in base64" window of the online tool

Run: `./aes_lab.sh`

## Part 1: Online encoding/decoding tool

Searching for "encrypt decrypt AES online" gives tools such as aesencryption.net, devglan.com/online-tools/aes-encryption-decryption, and cryptii.com. They all do the same thing: plaintext + secret key -> base64 ciphertext and back. For the lab I used OpenSSL, which implements the same AES algorithm locally (no need to paste a secret message into a third-party website).

## Part 2: Encrypt a message for the lab partner

Partner A plaintext:

```
LockBit affiliates use Citrix Bleed (CVE-2023-4966) for initial access. Patch NetScaler today.
```

Partner A ciphertext (key `netsec`):

```
U2FsdGVkX185w+Cw4OXjbh7YDSlU1fRA1WMSOGPqZw1761KvkntQdlnAc+kV0ov8JX3gQFkCkqAFO5ibS15koqkhoc+Ixvq0gJCDL86radJou3Lrm6ilSJjPv4Whp5MvYz8GjHkrtOxnJtYLQDLzYQ==
```

Partner B plaintext:

```
Meet at the SOC at 10:00, bring the MISP export.
```

Partner B ciphertext (key `netsec`):

```
U2FsdGVkX1+EkybviohXCB61jMrpJd2md44UklhGoihYwmlB/cMeocoq4m94f6gV72Ok+SwvCqidzpqMhMwuc/D0cXCIkT64ZXlYUU2d7lM=
```

The ciphertexts are what gets "emailed" to the partner. The ciphertext looks like random text and gives no hint about the message. Encrypting the same plaintext twice also gives two different ciphertexts, because a new random salt (and so a new key/IV) is used each time.

You can check them yourself:

```
echo 'U2FsdGVkX1+Ekybv...' | openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -base64 -A -pass pass:netsec
```

## Part 3: Decrypt the ciphertext

With the pre-shared key `netsec` each partner gets the original cleartext back:

```
B decrypts A's message -> LockBit affiliates use Citrix Bleed (CVE-2023-4966) for initial access. Patch NetScaler today.
A decrypts B's message -> Meet at the SOC at 10:00, bring the MISP export.
```

AES is symmetric: the same key encrypts and decrypts, so both partners had to agree on the key in advance, through a different channel than the one used for the ciphertext.

## Question

**What happens if you use a wrong secret key?**

The message cannot be decrypted. With the wrong key (`netsec1`, one character different) OpenSSL stops with `bad decrypt`, and the online tools show an empty result or an error. If the padding check is turned off (`-nopad`), the output is just random bytes with nothing in common with the original text. Even a key that differs by one character gives a completely different AES key, so the plaintext stays unreadable. That is the point: without the correct secret key the ciphertext is useless, and the only way in is guessing the key, so the key must be long and random and must be shared securely (a weak key like `netsec` could be brute-forced).
