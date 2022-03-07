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

import org.apache.shiro.lang.util.ByteSource;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for the {@link SecureRandomNumberGenerator} class.
 *
 * @since 1.1
 */
class SecureRandomNumberGeneratorTest {

    @Test
    public void testDefaultNextBytesSize() {
        SecureRandomNumberGenerator rng = new SecureRandomNumberGenerator();
        boolean negativeThrown = false;
        boolean zeroThrown = false;
        try {
            rng.setDefaultNextBytesSize(-1);
        } catch (IllegalArgumentException e) {
            negativeThrown = true;
        }

        try {
            rng.setDefaultNextBytesSize(0);
        } catch (IllegalArgumentException e) {
            zeroThrown = true;
        }

        assertTrue(negativeThrown);
        assertTrue(zeroThrown);

        ByteSource bs = rng.nextBytes();
        assertNotNull(bs);
        assertNotNull(bs.getBytes());
        assertEquals(SecureRandomNumberGenerator.DEFAULT_NEXT_BYTES_SIZE, bs.getBytes().length);

        rng.setDefaultNextBytesSize(64);
        assertNotNull(bs);
        bs = rng.nextBytes();
        assertNotNull(bs.getBytes());
        assertEquals(64, bs.getBytes().length);
    }

    @Test(expected=NullPointerException.class)
    public void testInvalidSecureRandomProperty() {
        SecureRandomNumberGenerator rng = new SecureRandomNumberGenerator();
        rng.setSecureRandom(null);
    }

    @Test
    public void testNextBytesWithSize() {
        SecureRandomNumberGenerator rng = new SecureRandomNumberGenerator();
        boolean negativeThrown = false;
        boolean zeroThrown = false;
        try {
            rng.nextBytes(-1);
        } catch (IllegalArgumentException e) {
            negativeThrown = true;
        }

        try {
            rng.nextBytes(0);
        } catch (IllegalArgumentException e) {
            zeroThrown = true;
        }

        assertTrue(negativeThrown);
        assertTrue(zeroThrown);

        ByteSource bs = rng.nextBytes(8);
        assertNotNull(bs);
        assertNotNull(bs.getBytes());
        assertEquals(8, bs.getBytes().length);
    }
}
