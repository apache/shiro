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
import org.apache.shiro.crypto.hash.DefaultHashService
import org.apache.shiro.crypto.hash.Hash
import org.apache.shiro.crypto.hash.Sha384Hash
import org.apache.shiro.crypto.hash.Sha512Hash
import org.apache.shiro.crypto.hash.format.HashFormatFactory
import org.apache.shiro.crypto.hash.format.HexFormat
import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable
import org.junit.jupiter.api.parallel.Isolated

import static org.easymock.EasyMock.*
import static org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for the {@link DefaultPasswordService} implementation.
 *
 * @since 1.2
 */
@Isolated
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
        assertFalse service.passwordsMatch(null, new Sha384Hash("test"))
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

    private static DefaultPasswordService createSha256Service() {
        def hashService = new DefaultHashService(defaultAlgorithmName: 'SHA-256')
        new DefaultPasswordService(hashService: hashService)
    }
}
