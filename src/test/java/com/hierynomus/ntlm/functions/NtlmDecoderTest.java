package com.hierynomus.ntlm.functions;

import com.hierynomus.ntlm.messages.*;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.buffer.Buffer;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


class NtlmDecoderTest {

    String recordedNegotiateToken = "NTLM TlRMTVNTUAABAAAAAYIIogAAAAAoAAAAAAAAACgAAAAFASgKAAAADw==";
    String recordedChallengeToken = "NTLM TlRMTVNTUAACAAAABgAGADgAAAAFgomiT/wTOGqjhNYAAAAAAAAAAJIAkgA+AAAABgGxHQAAAA9DAE8ATwACAAYAQwBPAE8AAQAYAEQATQBaAEMARwBOAE0ATwBTADAAMAAxAAQAEgBjAG8AbwAuAGwAbwBjAGEAbAADACwARABNAFoAQwBHAE4ATQBPAFMAMAAwADEALgBjAG8AbwAuAGwAbwBjAGEAbAAFABIAYwBvAG8ALgBsAG8AYwBhAGwABwAIAOGFCOlb8tkBAAAAAA==";
    String recordedAuthToken = "NTLM TlRMTVNTUAADAAAAGAAYAEgAAADCAMIAYAAAAAYABgAiAQAAJAAkACgBAAAAAAAATAEAAAAAAABMAQAABYKJogUBKAoAAAAPVc8cCYaE+tVik4+rtG74UfIWwO1x0mjqNjdEYzZyW3KEe45rLaMFSQEBAAAAAAAAUBcfq4ZI2gGj/c8SKaaqeAAAAAACAAYAQwBPAE8AAQAYAEMATwBPAEMARwBOAE0ATwBTADAAMAA3AAQAEgBjAG8AbwAuAGwAbwBjAGEAbAADACwAQwBPAE8AQwBHAE4ATQBPAFMAMAAwADcALgBjAG8AbwAuAGwAbwBjAGEAbAAFABIAYwBvAG8ALgBsAG8AYwBhAGwABwAIABd2GquGSNoBAAAAAAAAAABDAE8ATwBzAGEAXwB3AGUAYgBzAGUAcgB2AGkAYwBlAF8AdABlAHMAdAA=";


    @Test
    void decodeKnownNegotiateToken() throws IOException {
        Buffer.PlainBuffer preparedToken = Utils.prepareAuthToken(recordedNegotiateToken);
        NtlmNegotiate decodedChallenge = new NtlmNegotiate();
        decodedChallenge.read(preparedToken);
//        decodedChallenge.read(preparedToken);

//        The expected values are taken from Wiresharks decoding of the token
//        Assertions.assertThat(ByteArrayUtils.printHex(decodedChallenge.getServerChallenge())).isEqualTo("4f fc 13 38 6a a3 84 d6");
//        Assertions.assertThat(decodedChallenge.getTargetName()).isEqualTo("COO");

        System.out.println(decodedChallenge);
    }

    @Test
    void decodeKnownChallengeToken() throws Buffer.BufferException, IOException {
        NtlmChallenge decodedChallenge = new NtlmChallenge();
        Buffer.PlainBuffer preparedToken = Utils.prepareAuthToken(recordedChallengeToken);
        decodedChallenge.read(preparedToken);

//        The expected values are taken from Wiresharks decoding of the token
        Assertions.assertThat(ByteArrayUtils.printHex(decodedChallenge.getServerChallenge())).isEqualTo("4f fc 13 38 6a a3 84 d6");
        Assertions.assertThat(decodedChallenge.getTargetName()).isEqualTo("COO");

        System.out.println(decodedChallenge);
    }


    @Test
    void decodeKnownAuthToken() throws Buffer.BufferException, IOException {
        NtlmAuthenticate decodedAuthenticate = new NtlmAuthenticate();
        String expectedNtResponse = "36 37 44 63 36 72 5b 72 84 7b 8e 6b 2d a3 05 49 " +
                                    "01 01 00 00 00 00 00 00 50 17 1f ab 86 48 da 01 " +
                                    "a3 fd cf 12 29 a6 aa 78 00 00 00 00 02 00 06 00 " +
                                    "43 00 4f 00 4f 00 01 00 18 00 43 00 4f 00 4f 00 " +
                                    "43 00 47 00 4e 00 4d 00 4f 00 53 00 30 00 30 00 " +
                                    "37 00 04 00 12 00 63 00 6f 00 6f 00 2e 00 6c 00 " +
                                    "6f 00 63 00 61 00 6c 00 03 00 2c 00 43 00 4f 00 " +
                                    "4f 00 43 00 47 00 4e 00 4d 00 4f 00 53 00 30 00 " +
                                    "30 00 37 00 2e 00 63 00 6f 00 6f 00 2e 00 6c 00 " +
                                    "6f 00 63 00 61 00 6c 00 05 00 12 00 63 00 6f 00 " +
                                    "6f 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 07 00 " +
                                    "08 00 17 76 1a ab 86 48 da 01 00 00 00 00 00 00 " +
                                    "00 00";
        String expectedLmResponse = "55 cf 1c 09 86 84 fa d5 62 93 8f ab b4 6e f8 51 f2 16 c0 ed 71 d2 68 ea";


        Buffer.PlainBuffer preparedToken = Utils.prepareAuthToken(recordedAuthToken);
        decodedAuthenticate.read(preparedToken);

//        The expected values are taken from Wiresharks decoding of the token
        Assertions.assertThat(decodedAuthenticate.getUserName()).isEqualTo("sa_webservice_test");
        Assertions.assertThat(decodedAuthenticate.getDomainName()).isEqualTo("COO");
        Assertions.assertThat(decodedAuthenticate.getNtResponse()).isEqualTo(expectedNtResponse);
        Assertions.assertThat(decodedAuthenticate.getLmResponse()).isEqualTo(expectedLmResponse);

        System.out.println(decodedAuthenticate);
    }

    @Test
    void decodeExistingAuthTokens() throws URISyntaxException, IOException {
        Matcher matcher = null;
        //            read file that contains recorded auth tokens from actual network traffic
        ClassLoader classLoader = this.getClass().getClassLoader();
        Path filePath = Paths.get(classLoader.getResource("testFiles/auth_tokens.txt").toURI());
        String fileContent = Files.readString(filePath, StandardCharsets.UTF_8);
// split the tokens and decode each one
        Pattern pattern = Pattern.compile("Authorization: NTLM (.*)");
        matcher = pattern.matcher(fileContent);
        int matches = 0;
        while (matcher.find()) {
            try {
                matches++;
                NtlmAuthenticate decodedAuthenticate = new NtlmAuthenticate();
                String capturedToken = matcher.group(1);
                Buffer.PlainBuffer preparedToken = Utils.prepareAuthToken(capturedToken);
                decodedAuthenticate.read(preparedToken);
                System.out.println(matches + ": " + decodedAuthenticate);
            } catch (Buffer.BufferException e) {
                System.out.println(matches + ": Token is faulty: " + matcher.group(1));
            } catch (IllegalArgumentException e) {
                System.out.println(matches + ": Last unit does not have enough valid bits: " + matcher.group(1));
            }
        }
    }

    @Test
    void decodeUnknownToken() throws Buffer.BufferException, IOException {
        NtlmPacket message = Utils.read(recordedNegotiateToken);

        System.out.println(message);
    }
}
