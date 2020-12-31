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

package org.apache.shiro.crypto.hash.format

import org.apache.shiro.crypto.hash.BCryptHash
import org.apache.shiro.crypto.hash.Hash
import org.apache.shiro.lang.codec.OpenBSDBase64
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

import java.nio.charset.StandardCharsets

import static org.junit.jupiter.api.Assertions.*

class UnixCryptFormatTest {

    private static final byte[] PRECOMPUTED_SALT = [
            -10, -44, 37, -72, 40, 120, 88, 16, -116, 50, -54, -50,
            -84, 66, -87, -14
    ];
    private static final byte[] PRECOMPUTED_HASHDATA = [
            -65, 4, 25, -47, 47, -68, -66, -66, 21, -89, -4, -15,
            -16, 125, 25, -97, -123, 118, 73, -89, -71, 0, -128
    ];
    private static final int PRECOMPUTED_COST = 10;

    private final UnixCryptFormat bCryptFormat = new UnixCryptFormat();

    @Test
    void testFormatParseable() {
        // given
        // 'secret#shiro,password;Jo8opech' will work
        final String formattedBcryptString = '$unixcrypt$2y$10$7rOjsAf2U/AKKqpMpCIn6etuOXyQ86tp2Tn9xv6FyXl2T0QYc3.G.';

        // when
        final Hash hash = this.bCryptFormat.parse(formattedBcryptString);

        // then
        assertTrue(hash instanceof BCryptHash);
        final BCryptHash bCryptHash = (BCryptHash) hash;

        assertAll(
                { assertEquals("2y", hash.getAlgorithmName()) } as Executable,
                { assertEquals(PRECOMPUTED_COST, hash.getIterations()) } as Executable,
                { assertEquals(PRECOMPUTED_COST, bCryptHash.getCost()) } as Executable,
                { assertEquals(1024, bCryptHash.getRealIterations()) } as Executable,
                {
                    assertArrayEquals(
                            PRECOMPUTED_SALT,
                            hash.getSalt().getBytes()
                    )
                } as Executable,
                {
                    assertArrayEquals(
                            PRECOMPUTED_HASHDATA,
                            hash.getBytes()
                    )
                } as Executable
        );
    }

    @Test
    void testFormatValidHash() {
        // given
        final Hash bcryptHash = new BCryptHash(PRECOMPUTED_SALT, PRECOMPUTED_HASHDATA, PRECOMPUTED_COST);


        // when
        final String formatted = this.bCryptFormat.format(bcryptHash);

        // then
        assertTrue(formatted.startsWith('$unixcrypt$2y$10$'));
        assertFalse(formatted.contains('$$'));
        assertFalse(formatted.contains('='));
    }

    @Test
    void testBase64EncodeDecode() {
        // given
        final String str = 'pWgo8H6sknPlLLSO2KkaLCarFwi8kF6';
        final OpenBSDBase64.Default bcryptBase64 = new OpenBSDBase64.Default();

        // when
        final byte[] decode = bcryptBase64.decode(str.getBytes(StandardCharsets.ISO_8859_1));
        final byte[] encode = bcryptBase64.encode(decode);

        // then
        assertArrayEquals(str.getBytes(StandardCharsets.ISO_8859_1), encode);
    }

}
