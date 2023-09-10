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


import org.apache.shiro.lang.util.ByteSource
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for the {@link DefaultHashService} implementation.
 *
 * @since 1.2
 */
class DefaultHashServiceTest {

    @Test
    void testNullRequest() {
        assertNull createSha256Service().computeHash(null)
    }

    @Test
    void testDifferentAlgorithmName() {
        // given
        def newAlgorithm = 'SHA-512'
        def service = new DefaultHashService(defaultAlgorithmName: newAlgorithm)

        // when
        def hash = hash(service, "test")

        // then
        assertEquals newAlgorithm, hash.algorithmName
    }

    @Test
    void testRequestWithEmptySource() {
        def source = ByteSource.Util.bytes((byte[]) null)
        def request = new HashRequest.Builder().setSource(source).build()
        def service = createSha256Service()
        assertNull service.computeHash(request)
    }

    /**
     * Two different strings hashed with the same salt should result in two different
     * hashes.
     */
    @Test
    void testOnlyRandomSaltHash() {
        HashService service = createSha256Service();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password2", first.salt);
        assertFalse first == second
    }

    /**
     * If the same string is hashed twice and only base salt was supplied, hashed
     * result should be different in each case.
     */
    @Test
    void testBothSaltsRandomness() {
        HashService service = createSha256Service();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password");
        assertFalse first == second
    }

    /**
     * If a string is hashed and only base salt was supplied, random salt is generated.
     * Hash of the same string with generated random salt should return the
     * same result.
     */
    @Test
    void testBothSaltsReturn() {
        HashService service = createSha256Service();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password", first.salt);
        assertEquals first, second
    }

    /**
     * Two different strings hashed with the same salt should result in two different
     * hashes.
     */
    @Test
    void testBothSaltsHash() {
        HashService service = createSha256Service();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password2", first.salt);
        assertFalse first == second
    }

    protected Hash hash(HashService hashService, def source) {
        return hashService.computeHash(new HashRequest.Builder().setSource(source).build());
    }

    protected Hash hash(HashService hashService, def source, def salt) {
        return hashService.computeHash(new HashRequest.Builder().setSource(source).setSalt(salt).build());
    }

    private static DefaultHashService createSha256Service() {
        return new DefaultHashService(defaultAlgorithmName: 'SHA-256');
    }

}
