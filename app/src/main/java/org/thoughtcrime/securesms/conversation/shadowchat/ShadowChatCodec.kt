/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.conversation.shadowchat

import com.google.crypto.tink.subtle.XChaCha20Poly1305
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections

/**
 * ShadowChat v1 wire format:
 * Base64([magic(2)][version(2)][salt(16)][regularBlock][hiddenBlock])
 *
 * Each block is XChaCha20-Poly1305 output:
 * [24-byte nonce][X-byte ciphertext][16-byte tag]
 * where ciphertext is produced by encrypting a fixed-size (X bytes) padded payload:
 * [payloadLength(4)][payload bytes][random noise...]
 */
object ShadowChatCodec {

  private const val MAGIC_0: Byte = 0x53 // 'S'
  private const val MAGIC_1: Byte = 0x43 // 'C'

  private const val VERSION_V1: Short = 1

  private const val SALT_LENGTH_BYTES = 16
  private const val HEADER_LENGTH_BYTES = 2 + 2 + SALT_LENGTH_BYTES

  private const val NONCE_LENGTH_BYTES = 24
  private const val TAG_LENGTH_BYTES = 16
  private const val BLOCK_OVERHEAD_BYTES = NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES

  private const val PAYLOAD_HEADER_LENGTH_BYTES = 4

  private val BLOCK_SIZES: IntArray = intArrayOf(
    256,
    1024,
    8192,
    65536,
    524288
  )

  private const val ARGON2_ITERATIONS = 2
  private const val ARGON2_MEMORY_KIB = 24 * 1024
  private const val ARGON2_PARALLELISM = 1
  private const val KEY_LENGTH_BYTES = 32

  private val AAD_REGULAR = "shadowchat:v1:block:regular".toByteArray(StandardCharsets.UTF_8)
  private val AAD_HIDDEN = "shadowchat:v1:block:hidden".toByteArray(StandardCharsets.UTF_8)

  private const val KEY_CACHE_MAX_SIZE = 16

  private val keyCache: MutableMap<String, ByteArray> = Collections.synchronizedMap(
    object : LinkedHashMap<String, ByteArray>(KEY_CACHE_MAX_SIZE, 0.75f, true) {
      override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, ByteArray>?): Boolean {
        return size > KEY_CACHE_MAX_SIZE
      }
    }
  )

  data class DecodedLayers(
    val regular: String,
    val hidden: String? = null,
    val salt: ByteArray
  )

  sealed class EncodeFailure(message: String) : Exception(message) {
    data class RegularPasswordMissing(val ignored: Unit = Unit) : EncodeFailure("Regular password required")
    data class DecoyTooSmall(val requiredBlockSize: Int, val decoyBlockSize: Int) :
      EncodeFailure("Decoy too small (required=$requiredBlockSize, actual=$decoyBlockSize)")
  }

  /**
   * Encodes a ShadowChat message body.
   *
   * - Always emits both blocks.
   * - If [hiddenPassword] is null, the hidden block is filled with random bytes of the correct length.
   * - If [hiddenPlaintext] is non-null, [regularPlaintext] must reserve the same block size.
   */
  @JvmStatic
  fun encode(
    regularPlaintext: String,
    hiddenPlaintext: String?,
    regularPassword: CharArray?,
    hiddenPassword: CharArray?,
    secureRandom: SecureRandom = SecureRandom()
  ): String {
    if (regularPassword == null || regularPassword.isEmpty()) {
      throw EncodeFailure.RegularPasswordMissing()
    }

    val regularBytes = regularPlaintext.toByteArray(StandardCharsets.UTF_8)
    val hiddenBytes = hiddenPlaintext?.toByteArray(StandardCharsets.UTF_8)

    val regularBlockSize = selectBlockSize(regularBytes.size)
    val hiddenBlockSize = hiddenBytes?.let { selectBlockSize(it.size) } ?: regularBlockSize

    if (hiddenBytes != null && regularBlockSize != hiddenBlockSize) {
      throw EncodeFailure.DecoyTooSmall(requiredBlockSize = hiddenBlockSize, decoyBlockSize = regularBlockSize)
    }

    val blockSize = maxOf(regularBlockSize, hiddenBlockSize)

    val salt = ByteArray(SALT_LENGTH_BYTES).also(secureRandom::nextBytes)
    val header = buildHeader(salt)

    val regularKey = deriveKey(password = regularPassword, salt = salt, additional = AAD_REGULAR)
    val regularPayload = buildFixedSizePayload(blockSize = blockSize, messageBytes = regularBytes, secureRandom = secureRandom)
    val regularBlock = XChaCha20Poly1305(regularKey).encrypt(regularPayload, header + AAD_REGULAR)

    val hiddenBlock: ByteArray = if (hiddenPassword == null) {
      ByteArray(regularBlock.size).also(secureRandom::nextBytes)
    } else {
      val hiddenKey = deriveKey(password = hiddenPassword, salt = salt, additional = AAD_HIDDEN)
      val hiddenPayload = buildFixedSizePayload(blockSize = blockSize, messageBytes = hiddenBytes ?: ByteArray(0), secureRandom = secureRandom)
      XChaCha20Poly1305(hiddenKey).encrypt(hiddenPayload, header + AAD_HIDDEN)
    }

    val envelope = ByteArray(HEADER_LENGTH_BYTES + regularBlock.size + hiddenBlock.size)
    System.arraycopy(header, 0, envelope, 0, header.size)
    System.arraycopy(regularBlock, 0, envelope, header.size, regularBlock.size)
    System.arraycopy(hiddenBlock, 0, envelope, header.size + regularBlock.size, hiddenBlock.size)

    return envelope.toByteString().base64()
  }

  /**
   * Attempts to parse a ShadowChat envelope without performing any cryptography.
   */
  @JvmStatic
  fun isShadowChatEnvelope(body: CharSequence): Boolean {
    return tryParseEnvelope(body) != null
  }

  /**
   * Attempts to decode and decrypt ShadowChat layers.
   *
   * Returns null when:
   * - the input is not a ShadowChat envelope
   * - the regular layer cannot be decrypted (missing/wrong password)
   */
  @JvmStatic
  fun tryDecrypt(body: CharSequence, regularPassword: CharArray?, hiddenPassword: CharArray?): DecodedLayers? {
    if (regularPassword == null || regularPassword.isEmpty()) {
      return null
    }

    val parsed = tryParseEnvelope(body) ?: return null
    val (salt, regularBlock, hiddenBlock) = parsed

    val header = buildHeader(salt)

    val regularKey = deriveKey(password = regularPassword, salt = salt, additional = AAD_REGULAR)
    val regularPayload = try {
      XChaCha20Poly1305(regularKey).decrypt(regularBlock, header + AAD_REGULAR)
    } catch (_: Exception) {
      return null
    }
    val regularPlain = parseFixedSizePayload(regularPayload) ?: return null

    val hiddenPlain: String? = if (hiddenPassword == null || hiddenPassword.isEmpty()) {
      null
    } else {
      val hiddenKey = deriveKey(password = hiddenPassword, salt = salt, additional = AAD_HIDDEN)
      val hiddenPayload = try {
        XChaCha20Poly1305(hiddenKey).decrypt(hiddenBlock, header + AAD_HIDDEN)
      } catch (_: Exception) {
        null
      }
      hiddenPayload?.let { parseFixedSizePayload(it) }
    }

    return DecodedLayers(
      regular = regularPlain,
      hidden = hiddenPlain,
      salt = salt
    )
  }

  private data class ParsedEnvelope(
    val salt: ByteArray,
    val regularBlock: ByteArray,
    val hiddenBlock: ByteArray
  )

  private fun tryParseEnvelope(body: CharSequence): ParsedEnvelope? {
    val decoded = body.toString().decodeBase64()?.toByteArray() ?: return null

    if (decoded.size < HEADER_LENGTH_BYTES + 2 * (BLOCK_OVERHEAD_BYTES + BLOCK_SIZES.first())) {
      return null
    }

    if (decoded[0] != MAGIC_0 || decoded[1] != MAGIC_1) {
      return null
    }

    val version = ByteBuffer.wrap(decoded, 2, 2).order(ByteOrder.BIG_ENDIAN).short
    if (version != VERSION_V1) {
      return null
    }

    val salt = decoded.copyOfRange(4, 4 + SALT_LENGTH_BYTES)
    val remaining = decoded.size - HEADER_LENGTH_BYTES

    for (blockSize in BLOCK_SIZES) {
      val blockLength = BLOCK_OVERHEAD_BYTES + blockSize
      val totalBlocksLength = 2 * blockLength
      if (remaining == totalBlocksLength) {
        val regularStart = HEADER_LENGTH_BYTES
        val hiddenStart = regularStart + blockLength

        return ParsedEnvelope(
          salt = salt,
          regularBlock = decoded.copyOfRange(regularStart, regularStart + blockLength),
          hiddenBlock = decoded.copyOfRange(hiddenStart, hiddenStart + blockLength)
        )
      }
    }

    return null
  }

  private fun buildHeader(salt: ByteArray): ByteArray {
    val header = ByteArray(HEADER_LENGTH_BYTES)
    header[0] = MAGIC_0
    header[1] = MAGIC_1
    ByteBuffer.wrap(header, 2, 2).order(ByteOrder.BIG_ENDIAN).putShort(VERSION_V1)
    System.arraycopy(salt, 0, header, 4, SALT_LENGTH_BYTES)
    return header
  }

  private fun selectBlockSize(payloadBytesLength: Int): Int {
    val totalNeeded = PAYLOAD_HEADER_LENGTH_BYTES + payloadBytesLength
    return BLOCK_SIZES.firstOrNull { it >= totalNeeded }
      ?: throw IllegalArgumentException("Message too large ($payloadBytesLength bytes)")
  }

  private fun buildFixedSizePayload(blockSize: Int, messageBytes: ByteArray, secureRandom: SecureRandom): ByteArray {
    val payload = ByteArray(blockSize)
    ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN).putInt(messageBytes.size)
    System.arraycopy(messageBytes, 0, payload, PAYLOAD_HEADER_LENGTH_BYTES, messageBytes.size)

    val paddingStart = PAYLOAD_HEADER_LENGTH_BYTES + messageBytes.size
    if (paddingStart < blockSize) {
      val padding = ByteArray(blockSize - paddingStart).also(secureRandom::nextBytes)
      System.arraycopy(padding, 0, payload, paddingStart, padding.size)
    }
    return payload
  }

  private fun parseFixedSizePayload(payload: ByteArray): String? {
    if (payload.size < PAYLOAD_HEADER_LENGTH_BYTES) {
      return null
    }

    val length = ByteBuffer.wrap(payload, 0, PAYLOAD_HEADER_LENGTH_BYTES).order(ByteOrder.BIG_ENDIAN).int
    if (length < 0 || length > payload.size - PAYLOAD_HEADER_LENGTH_BYTES) {
      return null
    }

    val messageBytes = payload.copyOfRange(PAYLOAD_HEADER_LENGTH_BYTES, PAYLOAD_HEADER_LENGTH_BYTES + length)
    return String(messageBytes, StandardCharsets.UTF_8)
  }

  private fun deriveKey(password: CharArray, salt: ByteArray, additional: ByteArray): ByteArray {
    val cacheKey = computeCacheKey(password, salt, additional)

    keyCache[cacheKey]?.let { cachedKey ->
      return cachedKey.copyOf()
    }

    val passwordBytes = String(password).toByteArray(StandardCharsets.UTF_8)

    val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withSalt(salt)
      .withAdditional(additional)
      .withIterations(ARGON2_ITERATIONS)
      .withMemoryAsKB(ARGON2_MEMORY_KIB)
      .withParallelism(ARGON2_PARALLELISM)
      .build()

    val generator = Argon2BytesGenerator()
    generator.init(parameters)

    val out = ByteArray(KEY_LENGTH_BYTES)
    try {
      generator.generateBytes(passwordBytes, out)
      keyCache[cacheKey] = out.copyOf()
      return out
    } finally {
      passwordBytes.fill(0)
    }
  }

  private fun computeCacheKey(password: CharArray, salt: ByteArray, additional: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(String(password).toByteArray(StandardCharsets.UTF_8))
    digest.update(salt)
    digest.update(additional)
    return digest.digest().toByteString().hex()
  }

  @JvmStatic
  fun clearKeyCache() {
    keyCache.clear()
  }
}
