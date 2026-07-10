/*
 * crypto.h
 * ---------
 * ST5004CEM - Task 3: File System Operations and Security
 *
 * Provides:
 *   - SHA-256 hashing (used for password storage, never store plaintext)
 *   - A simple XOR stream cipher (used for file content encryption)
 *   - Salt generation
 *
 * SECURITY NOTE: The XOR cipher is used here to demonstrate the CONCEPT
 * of symmetric encryption/decryption within the file system (key-based,
 * reversible, changes ciphertext unpredictably without the key). It is
 * NOT cryptographically secure for real use — see docs/security_analysis.md
 * for a full discussion and recommended production alternatives
 * (e.g. AES-256-GCM via a vetted library such as OpenSSL or libsodium).
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include "common.h"

/* Computes SHA-256 of `data` (length `len`) into `out_hash` (32 bytes). */
void sha256(const unsigned char *data, size_t len, unsigned char out_hash[HASH_LEN]);

/* Fills `salt` with SALT_LEN cryptographically-reasonable random bytes. */
void generate_salt(unsigned char salt[SALT_LEN]);

/* Hashes a password with a salt: SHA-256(salt || password). */
void hash_password(const char *password, const unsigned char salt[SALT_LEN],
                    unsigned char out_hash[HASH_LEN]);

/* XOR-encrypts/decrypts `buffer` of `len` bytes in place, using a
 * repeating key derived from SHA-256(passphrase). XOR is symmetric,
 * so the same function is used for both encryption and decryption. */
void xor_cipher(unsigned char *buffer, size_t len, const char *passphrase);

/* Converts a raw byte buffer to a lowercase hex string (for printing/storing). */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *out_hex);

#endif
