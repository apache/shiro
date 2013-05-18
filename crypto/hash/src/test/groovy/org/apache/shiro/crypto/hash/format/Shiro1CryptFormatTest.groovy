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

import org.apache.shiro.crypto.SecureRandomNumberGenerator
import org.apache.shiro.crypto.hash.SimpleHash
import org.junit.Test
import static org.junit.Assert.*

/**
 * Unit tests for the {@link Shiro1CryptFormat} implementation.
 *
 * @since 1.2
 */
class Shiro1CryptFormatTest {

    @Test
    void testGetId() {
        assertEquals "shiro1", new Shiro1CryptFormat().getId()
    }

    @Test
    void testFormatDefault() {
        def format = new Shiro1CryptFormat();

        def alg = "SHA-512"
        def iterations = 10;
        def rng = new SecureRandomNumberGenerator()
        def source = rng.nextBytes()
        def salt = rng.nextBytes()

        def hash = new SimpleHash(alg, source, salt, iterations)

        String formatted = format.format(hash);

        String expected =
            Shiro1CryptFormat.MCF_PREFIX + alg + '$' + iterations + '$' + salt.toBase64() + '$' + hash.toBase64()

        assertNotNull formatted
        assertEquals expected, formatted
    }

    @Test
    void testFormatWithoutSalt() {
        def format = new Shiro1CryptFormat();

        def alg = "SHA-512"
        def iterations = 10;
        def rng = new SecureRandomNumberGenerator()
        def source = rng.nextBytes()

        def hash = new SimpleHash(alg, source, null, iterations)

        String formatted = format.format(hash);

        String expected = Shiro1CryptFormat.MCF_PREFIX + alg + '$' + iterations + '$$' + hash.toBase64()

        assertNotNull formatted
        assertEquals expected, formatted
    }

    @Test
    void testFormatWithNullArgument() {
        def format = new Shiro1CryptFormat()
        def result = format.format(null)
        assertNull result
    }

    @Test
    void testParseDefault() {
        def format = new Shiro1CryptFormat();
        def delim = Shiro1CryptFormat.TOKEN_DELIMITER

        def alg = "SHA-512"
        def iterations = 10;
        def rng = new SecureRandomNumberGenerator()
        def source = rng.nextBytes()
        def salt = rng.nextBytes()

        def hash = new SimpleHash(alg, source, salt, iterations)

        String formatted = Shiro1CryptFormat.MCF_PREFIX +
                alg + delim +
                iterations + delim +
                salt.toBase64() + delim +
                hash.toBase64()

        def parsedHash = format.parse(formatted)

        assertEquals hash, parsedHash
        assertEquals hash.algorithmName, parsedHash.algorithmName
        assertEquals hash.iterations, parsedHash.iterations
        assertEquals hash.salt, parsedHash.salt
        assertTrue Arrays.equals(hash.bytes, parsedHash.bytes)
    }

    @Test
    void testParseWithoutSalt() {
        def format = new Shiro1CryptFormat();
        def delim = Shiro1CryptFormat.TOKEN_DELIMITER

        def alg = "SHA-512"
        def iterations = 10;
        def rng = new SecureRandomNumberGenerator()
        def source = rng.nextBytes()

        def hash = new SimpleHash(alg, source, null, iterations)

        String formatted = Shiro1CryptFormat.MCF_PREFIX +
                alg + delim +
                iterations + delim +
                delim +
                hash.toBase64()

        def parsedHash = format.parse(formatted)

        assertEquals hash, parsedHash
        assertEquals hash.algorithmName, parsedHash.algorithmName
        assertEquals hash.iterations, parsedHash.iterations
        assertNull hash.salt
        assertTrue Arrays.equals(hash.bytes, parsedHash.bytes)
    }

    @Test
    void testParseWithNullArgument() {
        def format = new Shiro1CryptFormat()
        def result = format.parse(null)
        assertNull result
    }

    @Test
    void testParseWithInvalidId() {
        def format = new Shiro1CryptFormat()
        try {
            format.parse('$foo$xxxxxxx')
            fail("parse should have thrown an IllegalArgumentException")
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testParseWithNonNumericIterations() {
        def format = new Shiro1CryptFormat();
        def formatted = '$shiro1$SHA-512$N$foo$foo'

        try {
            format.parse(formatted)
            fail("parse should have thrown an IllegalArgumentException")
        } catch (IllegalArgumentException expected) {
        }
    }

}
