package io.iotex.ndktest

class IOConnect {

    companion object {
        init {
            System.loadLibrary("ndktest")
        }

        external fun main()
    }

}

