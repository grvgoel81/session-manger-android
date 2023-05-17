package com.web3auth.session_manager_android.types

import androidx.annotation.Keep

@Keep
data class ShareMetadata(
    val iv: String? = null,
    val ephemPublicKey: String? = null,
    val ciphertext: String? = null,
    val mac: String? = null
)