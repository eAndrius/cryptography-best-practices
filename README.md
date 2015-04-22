# Why The Guide?

This peer-reviewed and constantly updated guide aims to serve as a one-stop place for industry-best cryptography practices without requiring to read extensive books or rely on, usually insecure, default parameters.

If you think there is a better explanation or want to add additional guidelines do a pull request.

# General

Cryptography is mainly used for Encryption, Authentication (Signing) and Identification.

* `Encryption` - hiding plaintext from untrusted parties.
* `Authentication (Signing)` - preventing and discovering modifications to plaintext by untrusted parties.
* `Identification` - preventing impersonation by untrusted parties.

### DO
* Use TLS (succcesor of SSL) for transport.
* Use GPG for protecting data at rest.

### DON'T
* **Write custom cryptographic code.**

# Passwords

### DO
* Avoid using passwords whenever possible.
* Use a key derivation functions (PBKDF2/scrypt) to convert passwords as soon as possible.

### DON'T
* **Store passwords on the server, even if encrypted.**

# Hashing

[Hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) is an algorithm which maps arbitrary-lenght inputs to fixed-lenght outputs which are collision-resistant and one-way. Hashing guarantees the integrity of data.

### DO
* Use SHA-256.
* Use a hash when you can securely distribute *H(x)* and want to validate that a value *x'* that is received insecurely is in fact equal to *x*.

### DON'T
* Use MD2, MD5, MD5, SHA-1, RIPEMD.
* Use hash function as a symmetric signature.


# Symmetric Authentication (Signing)

Symmetric authentication is done by using [Message Authentication Code (MAC)](https://en.wikipedia.org/wiki/Message_authentication_code). A Message Authentication Code is an algorithm which takes as input a message and a secret key and produces a fixed-sized output which can be later on verified to match the message. Unlike hashing, knowing message authentication code F(k, x) does not allow to compute F(k, y) for some other y. MAC guarantees the integrity and authentication of data.

### DO
* Use HMAC-SHA256.
* Guarantee that there are not two different messages resulting in the same data being input to signing algorithm.

### DON'T
* Use CBC-MAC, Poly1305.
* Leak information via timing side channels while doing signature verification.

# Block Ciphers

Block Ciphers are usually used in symetric encryption. Block Cipher uses a key to bijectively map n-bit inputs x to n-bit outputs Ek (x) such that knowing pairs (x,
Ek (x)) doesn’t allow you to guess (x′, Ek′(x′)) for any (x′, k′) != (x, k).

### DO
* Use AES-256 (is vulnerable to related-key attack, but will not matter as long as other things are riht).
* Use CTR mode of operation.
* Use MAC to authenticate encrypted data *before* decrypting it.

### DON'T
* Use blowfish, DES, Triple-DES.
* Use block cipher in "raw", ECB modes of operation.

# Asymmetric Authentication

Asymmetric Authentication is an algorithm which takes a signing key to transform plaintext into ciphertext and a verification key to transform ciphertext into either the plaintext or "invalid signature". The signing key cannot be computed from the verification key, but the verification key can usually be computed from the singing key. Ciphertext usually consists of the plaintext plus the signature.

### DO
* Use RSASSA-PSS (RSA signing with Probabilistic Signature Scheme padding).
* Use a 2048-bit RSA key, a public exponent off 65537, and SHA256.


### DON'T
* Use PKCS v1.5 padding
* Use RSA without message padding.
* **Use the same RSA key for both authentication and encryption.**

# Asymmetric Encryption

Asymmetric Encryption is an algorithm which uses public key to transform plaintext into ciphertext and convert ciphertext to plaintext using the private key. Like asymmetric signing, just the opposite way around.

### DO
* Use RSAES-OAEP (RSA encryption with Optimal Asymmetric Encryption Padding).
* Use a 2048-bit RSA key, a public exponent of 65537, SHA256, and MGF1-SHA256.
* Generate a random key and apply symmectric encryption to the plaintext and then apply asymmetric encryption to the symmectric encryption key.

### DON'T
* Use PKCS v1.5 padding.
* Use RSA without message padding.

# SSL

### DO
* Use SSL to secure website, email and other public standard Internet-facing services.
* Distribute an asymmetric signature verification key (or its hash) with the client side of client-server software and use that to bootstrap the secure communication.


### DON'T
* Trust all certificate authorities.

# Side Channel Attacks

## Timing Attacks

### DO
* Use the following logic:
```c
for (x=i=0; i < MAC_len; i++)
    x |= MAC_computed[i] - MAC_received[i];
return (x ? MAC_IS_BAD : MAC_IS_GOOD);
```

### DON'T
* Have key or plaintext dependent branches (if, for, while...).

* Use the following logic:
```c
for (i=0; i < MAC_len; i++)
    if (MAC_computed[i] != MAC_received[i])
        return MAC_IS_BAD;
return MAC_IS_GOOD;
```
