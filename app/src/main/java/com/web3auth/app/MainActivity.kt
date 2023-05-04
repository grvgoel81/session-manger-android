package com.web3auth.app

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import com.web3auth.core.Web3Auth
import com.web3auth.core.types.*
import com.web3auth.session_manager_android.SessionManager
import java8.util.concurrent.CompletableFuture
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var sessionManager: SessionManager
    private lateinit var web3Auth: Web3Auth
    private lateinit var tvResponse: TextView
    private lateinit var btnLogin: Button
    private lateinit var btnLogout: Button
    private lateinit var sessionId: String
    private lateinit var btnSession: Button
    private lateinit var btnAuthorize: Button
    private var web3AuthResponse = Web3AuthResponse()
    private var sessionTime: Long = 86400

    private val gson = Gson()

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvResponse = findViewById(R.id.tvResponse)
        btnLogin = findViewById(R.id.btnLogin)
        btnLogout = findViewById(R.id.btnLogout)
        btnSession = findViewById(R.id.btnSession)
        btnAuthorize = findViewById(R.id.btnAuthorize)

        web3Auth = Web3Auth(
            Web3AuthOptions(context = this,
                clientId = getString(R.string.web3auth_project_id),
                network = Web3Auth.Network.MAINNET,
                redirectUrl = Uri.parse("torusapp://org.torusresearch.web3authexample/redirect"),
                whiteLabel = WhiteLabelData(  // Optional param
                    "Web3Auth Sample App", null, null, "en", true,
                    hashMapOf(
                        "primary" to "#123456"
                    )
                )
            )
        )

        web3Auth.setResultUrl(intent?.data)

        btnLogin.setOnClickListener {
            onClickLogin()
        }

        btnLogout.setOnClickListener {
            logout()
        }

        btnAuthorize.setOnClickListener {
            sessionManager = SessionManager(this.applicationContext)
            val sessionResponse: CompletableFuture<String> = sessionManager.authorizeSession(false)
            sessionResponse.whenComplete { response, error ->
                if (error == null) {
                    val tempJson = JSONObject(response)
                    tvResponse.text = tempJson.toString(4)
                } else {
                    Log.d("MainActivity_Web3Auth", error.message ?: "Something went wrong")
                }
            }
        }

        btnSession.setOnClickListener {
            sessionManager = SessionManager(this.applicationContext)
            // Sample data for create session
            val json = JSONObject()
            json.put("name", "Gaurav Goel")
            json.put("publicKey", "qwerty1234jhqwjg235n4n13jh35j3m4")
            json.put("email", "gaurav@tor.us")
            val sessionResponse: CompletableFuture<String> =
                sessionManager.createSession(json.toString(), 86400)
            sessionResponse.whenComplete { response, error ->
                if (error == null) {
                    sessionId = response
                    btnSession.visibility = View.GONE
                } else {
                    Log.d("MainActivity_Web3Auth", error.message ?: "Something went wrong")
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        web3Auth.setResultUrl(intent?.data)
    }

    private fun onClickLogin() {
        val selectedLoginProvider = Provider.GOOGLE
        val loginCompletableFuture: CompletableFuture<Web3AuthResponse> = web3Auth.login(LoginParams(selectedLoginProvider))

        loginCompletableFuture.whenComplete { loginResponse, error ->
            if (error == null) {
                val jsonObject = JSONObject(gson.toJson(loginResponse))
                tvResponse.text = jsonObject.toString(4)
                sessionId = loginResponse.sessionId.toString()
                loginResponse.sessionId?.let { useSessionManageSdk(it) }
            } else {
                // render login error UI
            }
        }
    }

    private fun useSessionManageSdk(sessionId: String) {
        sessionManager = SessionManager(this.applicationContext)
        sessionManager.saveSessionId(sessionId)
        val sessionResponse: CompletableFuture<String> = sessionManager.authorizeSession(true)
        sessionResponse.whenComplete { loginResponse, error ->
            if (error == null) {
                btnLogin.visibility = View.GONE
                btnLogout.visibility = View.VISIBLE
                val tempJson = JSONObject(loginResponse)
                tempJson.put("userInfo", tempJson.get("store"))
                tempJson.remove("store")
                web3AuthResponse =
                    gson.fromJson(tempJson.toString(), Web3AuthResponse::class.java)
                val jsonObject = JSONObject(gson.toJson(web3AuthResponse))
                tvResponse.text = jsonObject.toString(4)
            } else {
                Log.d("MainActivity_Web3Auth", error.message ?: "Something went wrong")
            }
        }
    }

    private fun logout() {
        sessionManager = SessionManager(this.applicationContext)
        sessionManager.invalidateSession()
        val sessionResponse: CompletableFuture<Boolean> = sessionManager.invalidateSession()
        sessionResponse.whenComplete { response, error ->
            if (error == null) {
                btnLogout.visibility = View.GONE
                btnLogin.visibility = View.VISIBLE
                tvResponse.text = "Logout"
            } else {
                Log.d("MainActivity_Web3Auth", error.message ?: "Something went wrong")
            }
        }
    }
}