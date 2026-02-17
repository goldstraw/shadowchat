/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.conversation.shadowchat

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isFalse
import assertk.assertions.isNotNull
import assertk.assertions.isNull
import assertk.assertions.isTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.SecureRandom

class ShadowChatCodecTest {

  private val random = SecureRandom()

  @Test
  fun regularOnly_roundTrip() {
    val encoded = ShadowChatCodec.encode(
      regularPlaintext = "hello regular",
      hiddenPlaintext = null,
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = null,
      secureRandom = random
    )

    assertThat(ShadowChatCodec.isShadowChatEnvelope(encoded)).isTrue()

    val decoded = ShadowChatCodec.tryDecrypt(
      body = encoded,
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = null
    )

    assertThat(decoded).isNotNull()
    assertThat(decoded!!.regular).isEqualTo("hello regular")
    assertThat(decoded.hidden).isNull()
    assertThat(decoded.salt.size).isEqualTo(16)
  }

  @Test
  fun hiddenMode_roundTrip() {
    val encoded = ShadowChatCodec.encode(
      regularPlaintext = "decoy text",
      hiddenPlaintext = "secret text",
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = "hidden-pass".toCharArray(),
      secureRandom = random
    )

    val decodedBoth = ShadowChatCodec.tryDecrypt(
      body = encoded,
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = "hidden-pass".toCharArray()
    )

    assertThat(decodedBoth).isNotNull()
    assertThat(decodedBoth!!.regular).isEqualTo("decoy text")
    assertThat(decodedBoth.hidden).isEqualTo("secret text")

    val decodedRegularOnly = ShadowChatCodec.tryDecrypt(
      body = encoded,
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = null
    )

    assertThat(decodedRegularOnly).isNotNull()
    assertThat(decodedRegularOnly!!.regular).isEqualTo("decoy text")
    assertThat(decodedRegularOnly.hidden).isNull()
  }

  @Test
  fun wrongRegularPassword_returnsNull() {
    val encoded = ShadowChatCodec.encode(
      regularPlaintext = "decoy text",
      hiddenPlaintext = "secret text",
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = "hidden-pass".toCharArray(),
      secureRandom = random
    )

    val decoded = ShadowChatCodec.tryDecrypt(
      body = encoded,
      regularPassword = "wrong-pass".toCharArray(),
      hiddenPassword = null
    )

    assertThat(decoded).isNull()
  }

  @Test
  fun wrongHiddenPassword_hidesHiddenLayer() {
    val encoded = ShadowChatCodec.encode(
      regularPlaintext = "decoy text",
      hiddenPlaintext = "secret text",
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = "hidden-pass".toCharArray(),
      secureRandom = random
    )

    val decoded = ShadowChatCodec.tryDecrypt(
      body = encoded,
      regularPassword = "regular-pass".toCharArray(),
      hiddenPassword = "wrong-hidden".toCharArray()
    )

    assertThat(decoded).isNotNull()
    assertThat(decoded!!.regular).isEqualTo("decoy text")
    assertThat(decoded.hidden).isNull()
  }

  @Test
  fun decoyTooSmall_throws() {
    val hidden = "x".repeat(5000) // requires 8192
    val decoy = "x".repeat(100) // requires 256

    assertThrows(ShadowChatCodec.EncodeFailure.DecoyTooSmall::class.java) {
      ShadowChatCodec.encode(
        regularPlaintext = decoy,
        hiddenPlaintext = hidden,
        regularPassword = "regular-pass".toCharArray(),
        hiddenPassword = "hidden-pass".toCharArray(),
        secureRandom = random
      )
    }
  }

  @Test
  fun isShadowChatEnvelope_rejectsNonShadowChat() {
    assertThat(ShadowChatCodec.isShadowChatEnvelope("not base64")).isFalse()
  }
}
