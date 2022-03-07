/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.crypto.cipher


import org.apache.shiro.lang.codec.CodecSupport
import org.apache.shiro.lang.util.ByteSource
import org.apache.shiro.lang.util.Destroyable
import org.apache.shiro.util.ByteUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test

import java.security.Security

import static org.junit.Assert.assertTrue

/**
 * Test class for the AesCipherService class.
 *
 * @since 1.0
 */
class AesCipherServiceTest {

    private static final String[] PLAINTEXTS = [
        "Hello, this is a test.",
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    ]

    AesCipherServiceTest() {
        Security.addProvider(new BouncyCastleProvider())
    }

    @Test
    void testBlockOperations() {
        AesCipherService cipher = new AesCipherService()
        assertBlock(cipher)
    }

    @Test
    void testBlockOperations_ByteSource() {
        AesCipherService aes = new AesCipherService();

        byte[] key = aes.generateNewKey().getEncoded();

        for (String plain : PLAINTEXTS) {
            byte[] plaintext = CodecSupport.toBytes(plain);
            ByteSource ciphertext = aes.encrypt(plaintext, key);
            ByteSourceBroker broker = aes.decrypt(ciphertext.getBytes(), key);
            broker.useBytes(new ByteSourceUser() {
                @Override
                void use(byte[] bytes) {
                    assertTrue(Arrays.equals(plaintext, bytes));
                }
            });
            if (broker instanceof Destroyable) {
                ((Destroyable) broker).destroy();
            }
        }
    }

    @Test
    void testStreamingOperations() {
        AesCipherService cipher = new AesCipherService()
        assertStreaming(cipher)
    }

    @Test
    void testStreamingOperations_ByteSource() {

        AesCipherService cipher = new AesCipherService();
        byte[] key = cipher.generateNewKey().getEncoded();

        for (String plain : PLAINTEXTS) {
            byte[] plaintext = CodecSupport.toBytes(plain);
            InputStream plainIn = new ByteArrayInputStream(plaintext);
            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            cipher.encrypt(plainIn, cipherOut, key);

            byte[] ciphertext = cipherOut.toByteArray();
            InputStream cipherIn = new ByteArrayInputStream(ciphertext);
            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            cipher.decrypt(cipherIn, plainOut, key);

            byte[] decrypted = plainOut.toByteArray();
            try {
                assertTrue(Arrays.equals(plaintext, decrypted));
            } finally {
                ByteUtils.wipe(decrypted);
            }
        }
    }

    @Test
    void testAesGcm() {
        assertBlock(OperationMode.GCM)
        assertStreaming(OperationMode.GCM)
    }

    @Test
    void testCcm() {
        assertBlock(OperationMode.CCM, PaddingScheme.NONE, 13 * 8) // 13 bytes
        assertStreaming(OperationMode.CCM)
    }

    @Test
    void testCfb() {
        assertBlock(OperationMode.CFB)
        assertStreaming(OperationMode.CFB)
    }

    @Test
    void testCtr() {
        assertBlock(OperationMode.CTR)
        assertStreaming(OperationMode.CTR)
    }

    @Test
    void testEax() {
        assertBlock(OperationMode.EAX)
        assertStreaming(OperationMode.EAX)
    }

    @Test
    void testEcb() {
        assertBlock(OperationMode.ECB, PaddingScheme.PKCS5)
    }

    @Test
    void testNone() {
        assertBlock((OperationMode) null, null)
    }

    @Test
    void testOcb() {
        assertBlock(OperationMode.OCB, PaddingScheme.NONE, 15 * 8) // 15 bytes
        assertStreaming(OperationMode.OCB, PaddingScheme.NONE, 16 * 8) // 16 bytes
    }

    @Test
    void testOfb() {
        assertBlock(OperationMode.OFB)
        assertStreaming(OperationMode.OFB)
    }

    @Test
    void testPcbc() {
        assertBlock(OperationMode.PCBC, PaddingScheme.PKCS5)
        assertStreaming(OperationMode.PCBC, PaddingScheme.PKCS5)
    }

    private static assertBlock(OperationMode mode, PaddingScheme scheme = PaddingScheme.NONE, int ivSize = JcaCipherService.DEFAULT_KEY_SIZE) {
        AesCipherService cipher = new AesCipherService()
        cipher.setInitializationVectorSize(ivSize)

        if (mode == null) {
            cipher.setModeName(null)
        } else {
            cipher.setMode(mode)
        }

        if (scheme == null) {
            cipher.setPaddingSchemeName(null)
        } else {
            cipher.setPaddingScheme(scheme)
        }
        assertBlock(cipher)
    }

    private static assertStreaming(OperationMode mode, PaddingScheme scheme = PaddingScheme.NONE, int ivSize = JcaCipherService.DEFAULT_KEY_SIZE) {
        AesCipherService cipher = new AesCipherService()
        cipher.setInitializationVectorSize(ivSize)

        if (mode == null) {
            cipher.setStreamingModeName(null)
        } else {
            cipher.setStreamingMode(mode)
        }

        if (scheme == null) {
            cipher.setStreamingPaddingScheme(null)
        } else {
            cipher.setStreamingPaddingScheme(scheme)
        }
        assertBlock(cipher)
    }

    private static assertBlock(AesCipherService cipher, byte[] key = cipher.generateNewKey().getEncoded()) {
        for (String plain : PLAINTEXTS) {
            byte[] plaintext = CodecSupport.toBytes(plain)
            ByteSource ciphertext = cipher.encrypt(plaintext, key)
            ByteSourceBroker decrypted = cipher.decrypt(ciphertext.getBytes(), key)
            assertTrue(Arrays.equals(plaintext, decrypted.getClonedBytes()))
        }
    }

    private static assertStreaming(AesCipherService cipher, byte[] key = cipher.generateNewKey().getEncoded()) {
        for (String plain : PLAINTEXTS) {
            byte[] plaintext = CodecSupport.toBytes(plain)
            InputStream plainIn = new ByteArrayInputStream(plaintext)
            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream()
            cipher.encrypt(plainIn, cipherOut, key)

            byte[] ciphertext = cipherOut.toByteArray()
            InputStream cipherIn = new ByteArrayInputStream(ciphertext)
            ByteArrayOutputStream plainOut = new ByteArrayOutputStream()
            cipher.decrypt(cipherIn, plainOut, key)

            byte[] decrypted = plainOut.toByteArray()
            assertTrue(Arrays.equals(plaintext, decrypted))
        }
    }
}
