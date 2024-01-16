package com.hierynomus.ntlm.functions;

import com.hierynomus.ntlm.messages.NtlmAuthenticate;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class NtlmDecoderTest {

    @Test
    void decodeAuthToken() throws Buffer.BufferException {
        NtlmAuthenticate decodedAuthenticate = new NtlmAuthenticate();
//        FIXME Not taking care of the NTLM prefix ATM
//        String inputString1 = "NTLM TlRMTVNTUAADAAAAGAAYAEgAAADCAMIAYAAAAAYABgAiAQAAJAAkACgBAAAAAAAATAEAAAAAAABMAQAABYKJogUBKAoAAAAPkn1Ad9vmeXDs7QOuTZ/YFbd35olYYQCfgr7hlGC8dtszPt+OFy7nuAEBAAAAAAAA4I86IFBF2gE9RY5pB2WoVQAAAAACAAYAQwBPAE8AAQAYAEMATwBPAEMARwBOAE0ATwBTADAAMAA3AAQAEgBjAG8AbwAuAGwAbwBjAGEAbAADACwAQwBPAE8AQwBHAE4ATQBPAFMAMAAwADcALgBjAG8AbwAuAGwAbwBjAGEAbAAFABIAYwBvAG8ALgBsAG8AYwBhAGwABwAIACDbn55PRdoBAAAAAAAAAABDAE8ATwBzAGEAXwB3AGUAYgBzAGUAcgB2AGkAYwBlAF8AdABlAHMAdAA=";
        String inputString1 = "TlRMTVNTUAADAAAAGAAYAEgAAADCAMIAYAAAAAYABgAiAQAAJAAkACgBAAAAAAAATAEAAAAAAABMAQAABYKJogUBKAoAAAAPkn1Ad9vmeXDs7QOuTZ/YFbd35olYYQCfgr7hlGC8dtszPt+OFy7nuAEBAAAAAAAA4I86IFBF2gE9RY5pB2WoVQAAAAACAAYAQwBPAE8AAQAYAEMATwBPAEMARwBOAE0ATwBTADAAMAA3AAQAEgBjAG8AbwAuAGwAbwBjAGEAbAADACwAQwBPAE8AQwBHAE4ATQBPAFMAMAAwADcALgBjAG8AbwAuAGwAbwBjAGEAbAAFABIAYwBvAG8ALgBsAG8AYwBhAGwABwAIACDbn55PRdoBAAAAAAAAAABDAE8ATwBzAGEAXwB3AGUAYgBzAGUAcgB2AGkAYwBlAF8AdABlAHMAdAA=";
        byte[] decodedString = Base64.getDecoder().decode(inputString1);
        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(decodedString, Endian.LE);
        decodedAuthenticate.read(buffer);

        System.out.println(decodedAuthenticate.toString());
    }
}
