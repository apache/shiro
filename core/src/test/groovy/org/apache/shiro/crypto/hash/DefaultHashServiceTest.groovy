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

import org.apache.shiro.crypto.RandomNumberGenerator
import org.apache.shiro.crypto.SecureRandomNumberGenerator
import org.apache.shiro.util.ByteSource
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link DefaultHashService} implementation.
 *
 * @since 1.2
 */
class DefaultHashServiceTest extends GroovyTestCase {

    void testNullRequest() {
        assertNull createService().computeHash(null)
    }

    void testDifferentAlgorithmName() {
        def service = new DefaultHashService(hashAlgorithmName: 'MD5')
        def hash = hash(service, "test")
        assertEquals 'MD5', hash.algorithmName
    }

    void testDifferentIterations() {
        def service = new DefaultHashService(hashIterations: 2)
        def hash = hash(service, "test")
        assertEquals 2, hash.iterations
    }

    void testDifferentRandomNumberGenerator() {

        def ByteSource randomBytes = new SecureRandomNumberGenerator().nextBytes()
        def rng = createMock(RandomNumberGenerator)
        expect(rng.nextBytes()).andReturn randomBytes

        replay rng

        def service = new DefaultHashService(randomNumberGenerator: rng, generatePublicSalt: true)
        hash(service, "test")

        verify rng
    }

    /**
     * If 'generatePublicSalt' is true, 2 hashes of the same input source should be different.
     */
    void testWithRandomlyGeneratedSalt() {
        def service = new DefaultHashService(generatePublicSalt: true)
        def first = hash(service, "password")
        def second = hash(service, "password")
        assertFalse first == second
    }

    void testRequestWithEmptySource() {
        def source = ByteSource.Util.bytes((byte[])null)
        def request = new HashRequest.Builder().setSource(source).build()
        def service = createService()
        assertNull service.computeHash(request)
    }

    /**
     * Two different strings hashed with the same salt should result in two different
     * hashes.
     */
    void testOnlyRandomSaltHash() {
        HashService service = createService();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password2", first.salt);
        assertFalse first == second
    }

    /**
     * If the same string is hashed twice and only base salt was supplied, hashed
     * result should be different in each case.
     */
    void testBothSaltsRandomness() {
        HashService service = createServiceWithPrivateSalt();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password");
        assertFalse first == second
    }

    /**
     * If a string is hashed and only base salt was supplied, random salt is generated.
     * Hash of the same string with generated random salt should return the
     * same result.
     */
    void testBothSaltsReturn() {
        HashService service = createServiceWithPrivateSalt();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password", first.salt);
        assertEquals first, second
    }

    /**
     * Two different strings hashed with the same salt should result in two different
     * hashes.
     */
    void testBothSaltsHash() {
        HashService service = createServiceWithPrivateSalt();
        Hash first = hash(service, "password");
        Hash second = hash(service, "password2", first.salt);
        assertFalse first == second
    }

    /**
     * Hash result is different if the base salt is added.
     */
    public void testPrivateSaltChangesResult() {
        HashService saltedService = createServiceWithPrivateSalt();
        HashService service = createService();
        Hash first = hashPredictable(saltedService, "password");
        Hash second = hashPredictable(service, "password");
        assertFalse first == second
    }

    protected Hash hash(HashService hashService, def source) {
        return hashService.computeHash(new HashRequest.Builder().setSource(source).build());
    }

    protected Hash hash(HashService hashService, def source, def salt) {
        return hashService.computeHash(new HashRequest.Builder().setSource(source).setSalt(salt).build());
    }

    private Hash hashPredictable(HashService hashService, def source) {
        byte[] salt = new byte[20];
        Arrays.fill(salt, (byte) 2);
        return hashService.computeHash(new HashRequest.Builder().setSource(source).setSalt(salt).build());
    }

    private DefaultHashService createService() {
        return new DefaultHashService();
    }

    private DefaultHashService createServiceWithPrivateSalt() {
        DefaultHashService defaultHashService = new DefaultHashService();
        defaultHashService.setPrivateSalt(new SecureRandomNumberGenerator().nextBytes());
        return defaultHashService;
    }
}
