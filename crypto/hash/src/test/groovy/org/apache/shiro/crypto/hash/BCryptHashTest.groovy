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

package org.apache.shiro.crypto.hash

import org.junit.jupiter.api.Test

import java.security.SecureRandom

import static java.lang.Math.pow
import static org.junit.jupiter.api.Assertions.assertArrayEquals
import static org.junit.jupiter.api.Assertions.assertEquals

class BCryptHashTest {

    private static final String TEST_PASSWORD = "secret#shiro,password;Jo8opech";

    @Test
    void testCreateHashGenerateSaltIterations() {
        // given
        final def testPasswordChars = TEST_PASSWORD.toCharArray();

        // when
        final def bCryptHash = BCryptHash.generate testPasswordChars;

        // then
        assertEquals BCryptHash.DEFAULT_COST, bCryptHash.cost;
    }

    @Test
    void testCreateHashGivenSalt() {
        // given
        final def testPasswordChars = TEST_PASSWORD.toCharArray();
        final def salt = new SecureRandom().generateSeed 16;
        final def cost = 6

        // when
        final def bCryptHash = BCryptHash.generate(testPasswordChars, salt, cost);

        // then
        assertEquals cost, bCryptHash.cost;
        assertEquals pow(2, cost) as int, bCryptHash.iterations;
        assertArrayEquals salt, bCryptHash.salt.bytes;
    }

}
