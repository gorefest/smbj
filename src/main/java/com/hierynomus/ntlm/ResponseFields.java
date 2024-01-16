package com.hierynomus.ntlm;


/**
 * Helper class for storing information when reading an NtlmAuthenticate Message
 */

public class ResponseFields {

    private int responseLen;
    private int responseMaxLen;
    private long bufferOffset;

    public int getResponseLen() {
        return responseLen;
    }

    public void setResponseLen(int responseLen) {
        this.responseLen = responseLen;
    }

    public int getResponseMaxLen() {
        return responseMaxLen;
    }

    public void setResponseMaxLen(int responseMaxLen) {
        this.responseMaxLen = responseMaxLen;
    }

    public long getBufferOffset() {
        return bufferOffset;
    }

    public void setBufferOffset(long bufferOffset) {
        this.bufferOffset = bufferOffset;
    }
}
