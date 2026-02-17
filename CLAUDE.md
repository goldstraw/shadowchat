## Architecture Overview

### Core Purpose
ShadowChat implements **plausibly deniable encrypted messaging** , inspired by VeraCrypt's hidden volumes.
- **Regular conversation**: First encryption layer (can be shared when extorted under duress)
- **Optional hidden conversation**: Second encryption layer (typically used for highly sensitive conversation)

The system should be designed such that it is fundamentally impossible to prove whether a hidden conversation exists.
This means that a conversation with a hidden layer should not be distinguishable from one without it, even under scrutiny.

ShadowChat leverages Signal to establish secure message delivery channels, while the message content itself is protected using the dual-layer encryption scheme described below.

### User Flow (Regular Use Case)
1. User agrees upon a password with their contact.
2. User sends messages using the password.

### User Flow (Hidden Layer Use Case)
1. User agrees upon a regular password, and a **hidden password** with their contact.
2. When sending a sensitive message, the user encrypts it with the hidden password.
3. At the same time, the user encrypts a decoy message with the regular password.
   a. Validation checks ensure that the decoy content would have occupied the same space as it does with the hidden content included.
   b. This ensures that the existence of the hidden layer cannot be proven or disproven.
4. When decrypting in private, the recipient enters both passwords to view and responds to both layers.
5. When under duress, the user can provide only the regular password to reveal the decoy content, while denying the existence of any hidden layer.

### Cryptographic Guarantees
Confidentiality - XChaCha20-Poly1305 with Argon2id KDF
Deniability of Hidden Layer - There is no way to distinguish whether a hidden layer exists or not, even with access to the host machine.
Compromise Resistance - Password-based key derivation
The encrypted random noise to pad to a certain block size is indistinguishable from the actual encrypted content to prevent size-based attacks.
No forward secrecy - as we use password-based encryption, forward secrecy is not applicable assuming access to the device. Messages in transit are protected by Signal's protocol.

### Encryption Model
Password-based encryption is used to encrypt messages on top of Signal as opposed to public key encryption.
This allows the host machine to be compromised without revealing any decryption keys, as the user must remember their passwords.

This password is used to derive keys for XChaCha20-Poly1305 encryption.
Keys are derived with Argon2id using the per-message salt and an "additional" parameter that differs per layer (regular vs hidden) for domain separation.

AEAD AAD binds the ciphertext to the envelope header and the intended layer: AAD = [magic||version||salt] || layerLabel.

To prevent the size of messages from revealing the existence of a hidden layer, the system will reserve space for potential
hidden content, regardless of whether the hidden layer is used or not.
Block sizes should scale.
If your regular message is between 0 and 1024 bytes, 1024 bytes will be reserved for potential hidden content.
If your regular message is between 1024 and 8192 bytes, you must reserve 8192 bytes for the hidden content, and so on.
This allows for lee-way in how much decoy content is required for a given hidden message, while remaining efficient in storage.


### Encryption Algorithms
Despite specific choices here, the system is designed to be flexible and allow for future changes in encryption algorithms.

#### Key Derivation
To derive keys from passwords, Argon2id is used as it is a modern, memory-hard key derivation function.
Argon2id uses the Argon2 “associated data (AD)” input (not concatenation). This requires an Argon2 implementation that supports AD (e.g., BouncyCastle withAdditional).

#### Encryption
The system uses XChaCha20-Poly1305 for authenticated encryption, which provides both confidentiality and integrity.

#### Block Structure
The current implementation uses **block pairs** with structured headers.
Regardless of whether a hidden message is present, a regular block will always have a hidden pair block.

```
Unencrypted Envelope Header (20 bytes):
- magic (2 bytes): "SC"
- protocolVersion (2 bytes): big-endian short (v1 = 1)
- salt (16 bytes): per-message salt for Argon2id

Payload Header (inside encrypted payload, 4 bytes):
- payloadLength (4 bytes): big-endian int, length of meaningful plaintext bytes

Space for blocks is dynamically reserved based on the the size of the plaintext and header.
In XChaCha20-Poly1305, the ciphertext is the same length as the plaintext, with an additional 16 bytes for the authentication tag.
Block Sizes:
- 256 bytes
- 1024 bytes
- 8192 bytes
- 65536 bytes
- 524288 bytes

Block Pair Layout (on the wire):
Base64([magic(2)][version(2)][salt(16)][regularBlock][hiddenBlock])

Where each block is fixed-length based on the selected block size X:
blockLength = 24-byte nonce + X-byte ciphertext + 16-byte tag
```

### Algorithm Walkthrough

#### Pre-steps
1) User A and User B create accounts on the ShadowChat app.
2) User A and User B share a regular password and a hidden password securely

#### Sending a Message
3) User A wants to send a secret to User B.
    - Decide upon a protocol version with user B.
    - Derives a per-layer key using Argon2id(password, salt, additional=layerLabel).
    - Generate a header including metadata.
    - Use the size of the plaintext message and header to determine the block size.
    - Use the smallest block size that can accommodate the content.
    - Generates random noise to fill the rest of the block such that it is exactly the size of the reserved space.
    - Generate a fresh 24-byte nonce for the AEAD.
    - Encrypts using XChaCha20-Poly1305 with AAD = (envelopeHeader || layerLabel).
    - Constructs the final block pair: Base64([magic(2)][version(2)][salt(16)][regularBlock][hiddenBlock])
      - Where each block is [24-byte nonce][X-byte ciphertext][16-byte tag]
    - The user writes decoy message in order to reserve the same amount of space that the hidden message required. (If 1023 bytes of hidden content need to be sent, the user must write more than 256 bytes of decoy content to fit within the 1024-byte block size)
    - This decoy content, after the same encryption process (but with the regular password), must reserve the same block size that the hidden content needed to reserve.
    - Both the hidden and decoy content are sent to User B.

#### Receiving a Message (not under duress)
4) User B receives the message from User A
    - User B decrypts the content and uses the header to truncate the random noise.

#### Receiving a Message (under duress)
5) User B is under duress and cannot reveal the existence of the hidden layer.
    - User B decrypts the decoy content using the regular password.
    - User B can respond to User A with the decoy password, denying the existence of any hidden layer.


## Actual Parameters
- ARGON2_ALG=Argon2id
- ARGON2_ITERATIONS=2
- ARGON2_MEMORY_KIB=24576
- ARGON2_PARALLELISM=1
- ARGON2_KEY_LENGTH_BYTES=32

- SALT_LENGTH_BYTES=16

- AEAD_ALG=XChaCha20-Poly1305
- AEAD_NONCE_LENGTH_BYTES=24
- AEAD_TAG_LENGTH_BYTES=16

- AAD_REGULAR="shadowchat:v1:block:regular"
- AAD_HIDDEN="shadowchat:v1:block:hidden"

- BLOCK_SIZES_BYTES=[256,1024,8192,65536,524288]

- MAGIC="SC"
- PROTOCOL_VERSION=1