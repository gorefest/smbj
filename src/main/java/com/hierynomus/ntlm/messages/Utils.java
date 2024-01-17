/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.ntlm.messages;

import com.hierynomus.ntlm.ResponseFields;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.hierynomus.ntlm.functions.NtlmFunctions.unicode;

public class Utils {
    public static byte[] EMPTY = new byte[0];

    /**
     * Avoid instantiation.
     */
    private Utils() {}


    static int writeOffsettedByteArrayFields(Buffer.PlainBuffer buffer, byte[] bytes, int offset) {
        byte[] arr = bytes != null ? bytes : EMPTY;
        buffer.putUInt16(arr.length); // ArrayLen (2 bytes)
        buffer.putUInt16(arr.length); // ArrayMaxLen (2 bytes)
        buffer.putUInt32(offset); // ArrayOffset (4 bytes)
        return offset + arr.length;
    }

    static ResponseFields readOffsettedByteArrayFields(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        ResponseFields responseFields = new ResponseFields();
        responseFields.setResponseLen(buffer.readUInt16());
        responseFields.setResponseMaxLen(buffer.readUInt16());
        responseFields.setBufferOffset(buffer.readUInt32());
        return responseFields;
    }

    static byte[] ensureNotNull(byte[] possiblyNull) {
        return possiblyNull != null ? possiblyNull : EMPTY;
    }

    static byte[] ensureNotNull(String possiblyNull) {
        return possiblyNull != null ? unicode(possiblyNull) : EMPTY;
    }

    /**
     * Auth Tokens recorded from network traffic might contain an "NTLM" prefix and are base64 encoded
     */
    public static Buffer.PlainBuffer prepareAuthToken(String recordedToken) {
        byte[] removedNtlmPrefix = removeNtlmPrefix(recordedToken);
        byte[] decodedToken = Base64.getDecoder().decode(removedNtlmPrefix);
        return new Buffer.PlainBuffer(decodedToken, Endian.LE);
    }

    /**
     * Recorded tokens might contain a Prefix followed by a space. This has to be removed
     * @param recordedToken Decoded (plain) token with or without prefix
     * @return token without prefix
     */
    private static byte[] removeNtlmPrefix(String recordedToken) {
        // Splitting based on space
        String[] parts = recordedToken.split(" ");

        // Checking if there is a second part, if not, use the original input
        String resultString = (parts.length > 1) ? parts[1] : recordedToken;

        return resultString.getBytes(StandardCharsets.UTF_8);
    }
}
