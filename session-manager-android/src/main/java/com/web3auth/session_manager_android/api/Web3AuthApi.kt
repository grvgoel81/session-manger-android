package com.web3auth.session_manager_android.api

import com.web3auth.session_manager_android.models.SessionRequestBody
import com.web3auth.session_manager_android.models.StoreApiResponse
import org.json.JSONObject
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query

interface Web3AuthApi {

    @POST("/store/set")
    suspend fun createSession(@Body sessionRequestBody: SessionRequestBody): Response<JSONObject>

    @GET("/store/get")
    suspend fun authorizeSession(@Query("key") key: String): Response<StoreApiResponse>

    @POST("/store/set")
    suspend fun invalidateSession(@Body sessionRequestBody: SessionRequestBody): Response<JSONObject>
}