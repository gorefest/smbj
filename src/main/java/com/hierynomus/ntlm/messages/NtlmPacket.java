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

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.commons.buffer.Buffer;

import java.util.EnumSet;
import java.util.Set;

import static com.hierynomus.ntlm.messages.NtlmMessage.DEFAULT_FLAGS;
import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.*;

public class NtlmPacket implements Packet<Buffer.PlainBuffer> {

    protected static final int NTLMSSP_TYPE1 = 0x1;
    protected static final int NTLMSSP_TYPE2 = 0x2;
    protected static final int NTLMSSP_TYPE3 = 0x3;
    protected EnumSet<NtlmNegotiateFlag> negotiateFlags = EnumSet.of(NTLMSSP_NEGOTIATE_NTLM);

    protected static final String OEM_ENCODING = "cp850";
    protected static final String UNI_ENCODING = "UTF-16LE";


    protected static final byte[] NTLMSSP_SIGNATURE = new byte[] {
        (byte) 'N', (byte) 'T', (byte) 'L', (byte) 'M', (byte) 'S', (byte) 'S', (byte) 'P', (byte) 0
    };
    @Override
    public void write(Buffer.PlainBuffer buffer) {
        throw new UnsupportedOperationException("Not implemented by base class");
    }

    @Override
    public void read(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        throw new UnsupportedOperationException("Not implemented by base class");
    }


    static int readULong ( byte[] src, int index ) {
        return ( src[ index ] & 0xff ) | ( ( src[ index + 1 ] & 0xff ) << 8 ) | ( ( src[ index + 2 ] & 0xff ) << 16 )
            | ( ( src[ index + 3 ] & 0xff ) << 24 );
    }


    static int readUShort ( byte[] src, int index ) {
        return ( src[ index ] & 0xff ) | ( ( src[ index + 1 ] & 0xff ) << 8 );
    }



    static byte[] readSecurityBuffer ( byte[] src, int index ) {
        int length = readUShort(src, index);
        int offset = readULong(src, index + 4);
        byte[] buffer = new byte[length];
        System.arraycopy(src, offset, buffer, 0, length);
        return buffer;
    }


    protected void setFlags(int flags) {
        for (NtlmNegotiateFlag flag : NtlmNegotiateFlag.values()) {
            if ((flag.getValue() & flags) != 0) {
                negotiateFlags.add(flag);
            }
        }
    }

    public static int getFlags(EnumSet<NtlmNegotiateFlag> flags) {
        int result = 0;
        for (NtlmNegotiateFlag flag : flags) {
            result |= flag.getValue();
        }
        return result;
    }


    public static int getDefaultFlags(NtlmNegotiate type1) {
        if (type1 == null) {
            return getFlags(DEFAULT_FLAGS);
        }

        int flags = (int) NTLMSSP_NEGOTIATE_NTLM.getValue();
        int type1Flags = type1.getFlags(type1.negotiateFlags);
        flags |= ((type1Flags & NTLMSSP_NEGOTIATE_UNICODE.getValue()) != 0) ?
            NTLMSSP_NEGOTIATE_UNICODE.getValue() : NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.getValue();
        if ((type1Flags & NTLMSSP_REQUEST_TARGET.getValue()) != 0) {
            String domain = "coo";
            if (domain != null) {
                flags |= NTLMSSP_REQUEST_TARGET.getValue() | NTLMSSP_TARGET_TYPE_DOMAIN.getValue();
            }
        }
        return flags;
    }
}
