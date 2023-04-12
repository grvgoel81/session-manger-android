package com.web3auth.session_manager_android.types

class TorusException : Exception {
    constructor(msg: String?) : super(msg)
    constructor(msg: String?, err: Throwable?) : super(msg, err)
}