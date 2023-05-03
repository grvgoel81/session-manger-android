package com.web3auth.session_manager_android

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.annotation.RequiresApi
import androidx.core.os.postDelayed
import com.google.gson.GsonBuilder
import com.web3auth.session_manager_android.api.ApiHelper
import com.web3auth.session_manager_android.api.Web3AuthApi
import com.web3auth.session_manager_android.keystore.KeyStoreManager
import com.web3auth.session_manager_android.models.SessionRequestBody
import com.web3auth.session_manager_android.types.*
import com.web3auth.session_manager_android.types.Base64.encodeBytes
import java8.util.concurrent.CompletableFuture
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.*
import kotlin.math.min

class SessionManager(context: Context, sessionID: String, sessionTime: Long) {

    private val gson = GsonBuilder().disableHtmlEscaping().create()
    private var shareMetadata = ShareMetadata()
    private val web3AuthApi = ApiHelper.getInstance().create(Web3AuthApi::class.java)
    private var sessionId = sessionID
    private var minSessionTime: Long = 86400

    private var createSessionResponseCompletableFuture: CompletableFuture<String> =
        CompletableFuture()
    private var sessionCompletableFuture: CompletableFuture<String> = CompletableFuture()
    private var invalidateSessionCompletableFuture: CompletableFuture<Boolean> = CompletableFuture()

    init {
        KeyStoreManager.initializePreferences(context)
        initiateKeyStoreManager()

        if (sessionID.isNotEmpty()) {
            KeyStoreManager.savePreferenceData(
                KeyStoreManager.SESSION_ID,
                sessionID
            )
        }

        this.minSessionTime = min(sessionTime, 7 * 86400)
        sessionId = KeyStoreManager.getPreferencesData(KeyStoreManager.SESSION_ID).toString()
    }

    private fun initiateKeyStoreManager() {
        KeyStoreManager.getKeyGenerator()
    }

    @RequiresApi(Build.VERSION_CODES.O)
    @OptIn(DelicateCoroutinesApi::class)
    fun createSession(data: String): CompletableFuture<String> {
        val newSessionKey = KeyStoreManager.generateRandomSessionKey()
        try {
            val ephemKey = "04" + KeyStoreManager.getPubKey(newSessionKey)
            val ivKey = KeyStoreManager.randomString(32)
            val aes256cbc = AES256CBC(
                newSessionKey,
                ephemKey,
                ivKey
            )

            val encryptedData = aes256cbc.encrypt(data.toByteArray(StandardCharsets.UTF_8))
            val mac = aes256cbc.macKey
            val encryptedMetadata = ShareMetadata(ivKey, ephemKey, encryptedData, mac)
            val gsonData = gson.toJson(encryptedMetadata)

            GlobalScope.launch {
                val result = web3AuthApi.createSession(
                    SessionRequestBody(
                        key = "04".plus(KeyStoreManager.getPubKey(sessionId = newSessionKey)),
                        data = gsonData,
                        signature = KeyStoreManager.getECDSASignature(
                            BigInteger(newSessionKey, 16),
                            gsonData
                        ),
                        timeout = minSessionTime
                    )
                )
                if (result.isSuccessful) {
                    Handler(Looper.getMainLooper()).postDelayed(10) {
                        KeyStoreManager.savePreferenceData(
                            KeyStoreManager.SESSION_ID,
                            newSessionKey
                        )
                        createSessionResponseCompletableFuture.complete(newSessionKey)
                    }
                } else {
                    Handler(Looper.getMainLooper()).postDelayed(10) {
                        invalidateSessionCompletableFuture.completeExceptionally(
                            Exception(
                                SessionManagerError.getError(
                                    ErrorCode.SOMETHING_WENT_WRONG
                                )
                            )
                        )
                    }
                }
            }
        } catch (ex: Exception) {
            ex.printStackTrace()
            createSessionResponseCompletableFuture.completeExceptionally(ex)
        }
        return createSessionResponseCompletableFuture
    }

    /**
     * Authorize User session in order to avoid re-login
     */
    @OptIn(DelicateCoroutinesApi::class)
    fun authorizeSession(fromOpenLogin: Boolean): CompletableFuture<String> {
        sessionCompletableFuture = CompletableFuture()
        if(sessionId.isEmpty()) {
            sessionCompletableFuture.completeExceptionally(
                Exception(
                    SessionManagerError.getError(
                        ErrorCode.SESSIONID_NOT_FOUND
                    )
                )
            )
        }
        if (sessionId.isNotEmpty()) {
            val pubKey = "04".plus(KeyStoreManager.getPubKey(sessionId))
            GlobalScope.launch {
                try {
                    val result = web3AuthApi.authorizeSession(pubKey)
                    if (result.isSuccessful && result.body() != null) {
                        val messageObj = result.body()?.message?.let { JSONObject(it).toString() }
                        shareMetadata = gson.fromJson(
                            messageObj,
                            ShareMetadata::class.java
                        )

                        KeyStoreManager.savePreferenceData(
                            KeyStoreManager.EPHEM_PUBLIC_Key,
                            shareMetadata.ephemPublicKey.toString()
                        )
                        KeyStoreManager.savePreferenceData(
                            KeyStoreManager.IV_KEY,
                            shareMetadata.iv.toString()
                        )
                        KeyStoreManager.savePreferenceData(
                            KeyStoreManager.MAC,
                            shareMetadata.mac.toString()
                        )

                        val aes256cbc = AES256CBC(
                            sessionId,
                            shareMetadata.ephemPublicKey,
                            shareMetadata.iv.toString()
                        )

                        // Implementation specific oddity - hex string actually gets passed as a base64 string
                        val share: String = if(fromOpenLogin) {
                            val encryptedShareBytes =
                                AES256CBC.toByteArray(shareMetadata.ciphertext?.let { BigInteger(it, 16) })
                            aes256cbc.decrypt(encodeBytes(encryptedShareBytes))
                        } else {
                            aes256cbc.decrypt(shareMetadata.ciphertext)
                        }

                        Handler(Looper.getMainLooper()).postDelayed(10) {
                            sessionCompletableFuture.complete(share)
                        }
                    } else {
                        sessionCompletableFuture.completeExceptionally(
                            Exception(
                                SessionManagerError.getError(
                                    ErrorCode.SESSION_EXPIRED
                                )
                            )
                        )
                    }
                } catch (ex: Exception) {
                    ex.printStackTrace()
                    sessionCompletableFuture.completeExceptionally(
                        Exception(
                            SessionManagerError.getError(
                                ErrorCode.NOUSERFOUND
                            )
                        )
                    )
                }
            }
        }
        return sessionCompletableFuture
    }

    @OptIn(DelicateCoroutinesApi::class)
    fun invalidateSession(): CompletableFuture<Boolean> {
        invalidateSessionCompletableFuture = CompletableFuture()
        try {
            val ephemKey =
                KeyStoreManager.getPreferencesData(KeyStoreManager.EPHEM_PUBLIC_Key)
            val ivKey = KeyStoreManager.getPreferencesData(KeyStoreManager.IV_KEY)
            val mac = KeyStoreManager.getPreferencesData(KeyStoreManager.MAC)

            if (ephemKey?.isEmpty() == true && ivKey?.isEmpty() == true) {
                invalidateSessionCompletableFuture.complete(false)
            }

            val aes256cbc = AES256CBC(
                sessionId,
                ephemKey,
                ivKey.toString()
            )
            val encryptedData = aes256cbc.encrypt("".toByteArray(StandardCharsets.UTF_8))
            val encryptedMetadata = ShareMetadata(ivKey, ephemKey, encryptedData, mac)
            val gsonData = gson.toJson(encryptedMetadata)

            GlobalScope.launch {
                val result = web3AuthApi.invalidateSession(
                    SessionRequestBody(
                        key = "04".plus(KeyStoreManager.getPubKey(sessionId = sessionId)),
                        data = gsonData,
                        signature = KeyStoreManager.getECDSASignature(
                            BigInteger(sessionId, 16),
                            gsonData
                        ),
                        timeout = 1
                    )
                )
                if (result.isSuccessful) {
                    KeyStoreManager.deletePreferencesData(KeyStoreManager.SESSION_ID)
                    Handler(Looper.getMainLooper()).postDelayed(10) {
                        invalidateSessionCompletableFuture.complete(true)
                    }
                } else {
                    Handler(Looper.getMainLooper()).postDelayed(10) {
                        invalidateSessionCompletableFuture.completeExceptionally(
                            Exception(
                                SessionManagerError.getError(
                                    ErrorCode.SOMETHING_WENT_WRONG
                                )
                            )
                        )
                    }
                }
            }
        } catch (ex: Exception) {
            ex.printStackTrace()
            invalidateSessionCompletableFuture.completeExceptionally(ex)
        }
        return invalidateSessionCompletableFuture
    }
}