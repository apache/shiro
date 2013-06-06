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
package org.apache.shiro.crypto

import org.apache.shiro.codec.CodecSupport
import org.apache.shiro.util.ByteSource
import org.junit.Test

import static junit.framework.Assert.*

/**
 * Test class for the AesCipherService class.
 *
 * @since 1.0
 */
public class AesCipherServiceTest {

    private static final String[] PLAINTEXTS = [
        "Hello, this is a test.",
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    ];

    @Test
    public void testBlockOperations() {
        AesCipherService aes = new AesCipherService();

        byte[] key = aes.generateNewKey().getEncoded();

        for (String plain : PLAINTEXTS) {
            byte[] plaintext = CodecSupport.toBytes(plain);
            ByteSource ciphertext = aes.encrypt(plaintext, key);
            ByteSource decrypted = aes.decrypt(ciphertext.getBytes(), key);
            assertTrue(Arrays.equals(plaintext, decrypted.getBytes()));
        }
    }

    @Test
    public void testStreamingOperations() {

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
            assertTrue(Arrays.equals(plaintext, decrypted));
        }
    }
}
