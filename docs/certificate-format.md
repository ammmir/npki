# Certificate Format

NPKI uses a custom certificate format. To make copy-pasting easier, certificates MAY be serialized to [Base58](https://en.wikipedia.org/wiki/Base58), although binary encoding MUST be used when exchanging certificates over binary protocols. Any certificate presented to the user MUST be Base58 encoded. The npki command-line tool works exclusively with Base58-encoded certificates.

The root signing key is an Ed25519 key.

Servers use Curve25519 static keys.

Certificates are signed by the Ed25519 root signing key, certifying the server's Curve25519 public key.

All hashing operations use SHA-256, unless otherwise specified.

All lengths are in little-endian byte order.


## Certificate Structure

```
+-+-+-+-+-+-+-+-+
|    Version    |
+-+-+-+-+-+-+-+-+
|   Cert Type   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Valid From                             |
|                           Date                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Expiration                             |
|                           Date                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Cert Key Type |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                   Certified Public Key                        .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Ext Count   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                        Extension 0                            .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                            ...                                .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                        Extension N                            .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                         Signature                             .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* *Version*: specifies the certificate format version: `0x01`
* *Cert Type*: specifies the certificate type
  * `0x01`: signing a signing key with a signing key
  * `0x02`: signing an authentication key with a signing key
* *Valid From Date*: the number of seconds since the UNIX epoch
* *Expiration Date*: the number of seconds since the UNIX epoch
* *Cert Key Type*: specifies the certificate public key type to be signed
  * `0x01`: Ed25519 public key
  * `0x02`: DH25519 public key
* One or more extensions (defined below)
* *Signature*: The Ed25519 signature over all preceding fields in the certificate

The extensions are of the following format:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Extension Length       |    Ext Type   |   Ext Flags   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Extension Data
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

Signatures are computed from entire byte range of the certificate structure excluding the signature field.


## Extensions

### Signed-with-ed25519-key extension [type 01]

* *Extension Length*: 32 bytes
* *Extension Data*: 32-byte Ed25519 key
