/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc.credential

import org.apache.shiro.crypto.SecureRandomNumberGenerator
import org.apache.shiro.crypto.hash.*
import org.apache.shiro.crypto.hash.format.HashFormatFactory
import org.apache.shiro.crypto.hash.format.HexFormat
import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

import static org.easymock.EasyMock.*
import static org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for the {@link DefaultPasswordService} implementation.
 *
 * @since 1.2
 */
class DefaultPasswordServiceTest {

    @Test
    @DisplayName("throws NPE if plaintext is null")
    void testEncryptPasswordWithNullArgument() {
        def service = createSha256Service()

        assertThrows(NullPointerException, { service.encryptPassword(null) } as Executable)
    }

    @Test
    void testHashPasswordWithNullArgument() {
        def service = createSha256Service()
        assertNull service.hashPassword(null)
    }

    @Test
    void testEncryptPasswordDefault() {
        def service = createSha256Service()
        def encrypted = service.encryptPassword("12345")
        assertTrue service.passwordsMatch("12345", encrypted)
    }

    @Test
    void testEncryptPasswordWithInvalidMatch() {
        def service = createSha256Service()
        def encrypted = service.encryptPassword("ABCDEF")
        assertFalse service.passwordsMatch("ABC", encrypted)
    }

    @Test
    void testBackwardsCompatibility() {
        def service = createSha256Service()
        def encrypted = service.encryptPassword("12345")
        def submitted = "12345"
        assertTrue service.passwordsMatch(submitted, encrypted);

        //change some settings:
        service.hashService.defaultAlgorithmName = "MD5"

        def encrypted2 = service.encryptPassword(submitted)

        assertFalse encrypted == encrypted2

        assertTrue service.passwordsMatch(submitted, encrypted2)
    }

    @Test
    void testHashFormatWarned() {
        def service = createSha256Service()
        service.hashFormat = new HexFormat()
        assertTrue service.hashFormat instanceof HexFormat
        service.encryptPassword("test")
        assertTrue service.hashFormatWarned
    }

    @Test
    void testPasswordsMatchWithNullOrEmpty() {
        def service = createSha256Service()
        assertTrue service.passwordsMatch(null, (String) null)
        assertTrue service.passwordsMatch(null, (Hash) null)
        assertTrue service.passwordsMatch("", (String) null)
        assertTrue service.passwordsMatch(null, "")
        assertFalse service.passwordsMatch(null, "12345")
        assertFalse service.passwordsMatch(null, new Sha1Hash("test"))
    }

    @Test
    void testCustomHashService() {
        def hashService = createMock(HashService)

        def hash = new Sha256Hash("test", new SecureRandomNumberGenerator().nextBytes(), 100);

        expect(hashService.computeHash(isA(HashRequest))).andReturn hash

        replay hashService

        def service = new DefaultPasswordService()
        service.hashService = hashService

        def returnedHash = service.encryptPassword("test")

        assertEquals new Shiro1CryptFormat().format(hash), returnedHash

        verify hashService
    }

    @Test
    void testCustomHashFormatFactory() {

        def factory = createMock(HashFormatFactory)
        def hash = new Sha512Hash("test", new SecureRandomNumberGenerator().nextBytes(), 100)
        String saved = new Shiro1CryptFormat().format(hash)

        expect(factory.getInstance(eq(saved))).andReturn(new Shiro1CryptFormat())

        replay factory

        def service = new DefaultPasswordService()
        service.hashFormatFactory = factory

        assertSame factory, service.hashFormatFactory

        assertTrue service.passwordsMatch("test", saved)

        verify factory
    }

    @Test
    void testTurkishLocal() {

        Locale locale = Locale.getDefault();

        // tr_TR
        Locale.setDefault(new Locale("tr", "TR"));

        try {
            PasswordService passwordService = createSha256Service()
            String password = "333";
            String enc = passwordService.encryptPassword(password);
            assertTrue(passwordService.passwordsMatch(password, enc));
        }
        finally {
            Locale.setDefault(locale);
        }
    }

    private static DefaultPasswordService createSha256Service() {
        def hashService = new DefaultHashService(defaultAlgorithmName: 'SHA-256')
        new DefaultPasswordService(hashService: hashService)
    }
}
