package com.web3auth.session_manager_android.types

object SessionManagerError {

    fun getError(errorCode: ErrorCode): String {
        return when (errorCode) {
            ErrorCode.NOUSERFOUND -> {
                "No user found, please login again!"
            }
            ErrorCode.SESSIONID_NOT_FOUND -> {
                "SessionID not found!"
            }
            ErrorCode.ENCODING_ERROR -> {
                "Encoding Error"
            }
            ErrorCode.DECODING_ERROR -> {
                "Decoding Error"
            }
            ErrorCode.SOMETHING_WENT_WRONG -> {
                "Something went wrong!"
            }
            ErrorCode.RUNTIME_ERROR -> {
                "Runtime Error"
            }
            ErrorCode.SESSION_EXPIRED -> {
                "Session Expired or Invalid public key!"
            }
        }
    }
}

enum class ErrorCode {
    NOUSERFOUND,
    SESSIONID_NOT_FOUND,
    ENCODING_ERROR,
    DECODING_ERROR,
    RUNTIME_ERROR,
    SESSION_EXPIRED,
    SOMETHING_WENT_WRONG,
}