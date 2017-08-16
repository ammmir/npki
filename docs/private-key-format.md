# Private Key Format

NPKI uses a custom format to store private keys, optionally with encryption. To make copy-pasting easier, keys MAY be serialized to [Base58](https://en.wikipedia.org/wiki/Base58), but all keys must be stored and transmitted in binary form.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Type     |E|S|N| Reserved|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                              Key                              .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Checksum                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* *Type*: specifies the type of private key
  * `0x01`: Ed25519
  * `0x02`: DH25519
* *E*: private key is encrypted with the ChaCha20-Poly1305 AEAD cipher
* *S*: if **E=1**, indicates whether the symmetric key for the cipher is derived using the [scrypt](https://en.wikipedia.org/wiki/Scrypt) PBKDF; if set, implementations SHOULD prompt the user for a passphrase to decrypt the key
* *N*: whether or not *Key* is a private key nor not
* *Reserved*: reserved for future use, MUST be set to zero
* *Key*: if **N=0**, the private key, else if **N=1**, the public key
* *Checksum*: the first 4 bytes of the SHA-256 digest of the entire structure

All implementations MUST first compute and verify the checksum before accessing the private key.

All implementations SHOULD encrypt the private key.
