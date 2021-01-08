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

package org.apache.shiro.crypto.support.hashes.bcrypt

import org.apache.shiro.lang.util.SimpleByteSource
import org.junit.jupiter.api.Test

import java.nio.charset.StandardCharsets
import java.security.SecureRandom

import static java.lang.Math.pow
import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue

class BCryptHashTest {

    private static final String TEST_PASSWORD = "secret#shiro,password;Jo8opech";

    @Test
    void testCreateHashGenerateSaltIterations() {
        // given
        final def testPasswordChars = new SimpleByteSource(TEST_PASSWORD)

        // when
        final def bCryptHash = BCryptHash.generate testPasswordChars;

        // then
        assertEquals BCryptHash.DEFAULT_COST, bCryptHash.cost;
    }

    @Test
    void testCreateHashGivenSalt() {
        // given
        final def testPasswordChars = new SimpleByteSource(TEST_PASSWORD);
        final def salt = new SimpleByteSource(new SecureRandom().generateSeed(16))
        final def cost = 6

        // when
        final def bCryptHash = BCryptHash.generate(testPasswordChars, salt, cost);

        // then
        assertEquals cost, bCryptHash.cost;
        assertEquals pow(2, cost) as int, bCryptHash.iterations;
        assertEquals salt, bCryptHash.salt;
    }

    @Test
    void toBase64EqualsInput() {
        // given
        def salt = '7rOjsAf2U/AKKqpMpCIn6e'
        def saltBytes = new SimpleByteSource(new OpenBSDBase64.Default().decode(salt.getBytes(StandardCharsets.ISO_8859_1)))
        def testPwBytes = new SimpleByteSource(TEST_PASSWORD)
        def expectedHashString = '$2y$10$' + salt + 'tuOXyQ86tp2Tn9xv6FyXl2T0QYc3.G.'


        // when
        def bCryptHash = BCryptHash.generate("2y", testPwBytes, saltBytes, 10)

        // then
        assertEquals expectedHashString, bCryptHash.formatToCryptString()
    }

    @Test
    void testMatchesPassword() {
        // given
        def expectedHashString = '$2y$10$7rOjsAf2U/AKKqpMpCIn6etuOXyQ86tp2Tn9xv6FyXl2T0QYc3.G.'
        def bCryptHash = BCryptHash.fromString(expectedHashString)
        def testPwBytes = new SimpleByteSource(TEST_PASSWORD)

        // when
        def matchesPassword = bCryptHash.matchesPassword testPwBytes


        // then
        assertTrue matchesPassword
    }

}
