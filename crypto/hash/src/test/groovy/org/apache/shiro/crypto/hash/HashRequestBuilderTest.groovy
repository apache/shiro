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

import org.apache.shiro.crypto.SecureRandomNumberGenerator
import org.apache.shiro.lang.util.ByteSource
import org.junit.Test

import static org.junit.Assert.*

/**
 * Unit tests for the {@link HashRequest.Builder} implementation
 *
 * @since 1.2
 */
class HashRequestBuilderTest {

    @Test
    void testNullSource() {
        try {
            new HashRequest.Builder().build()
            fail "NullPointerException should be thrown"
        } catch (NullPointerException expected) {
        }
    }

    @Test
    void testDefault() {
        assertEquals 0, new HashRequest.Builder().setSource("test").build().iterations
    }

    @Test
    void testConfig() {
        ByteSource source = ByteSource.Util.bytes("test")
        ByteSource salt = new SecureRandomNumberGenerator().nextBytes()
        def request = new HashRequest.Builder()
            .setSource(source)
            .setSalt(salt)
            .setIterations(2)
            .setAlgorithmName('MD5').build()

        assertNotNull request
        assertEquals source, request.source
        assertEquals salt, request.salt
        assertEquals 2, request.iterations
        assertEquals 'MD5', request.algorithmName
    }
}
