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

import org.apache.shiro.crypto.hash.Hash
import org.apache.shiro.crypto.hash.Sha512Hash
import org.junit.jupiter.api.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThrows

/**
 * Unit tests for the {@link HexFormat} implementation.
 *
 * @since 1.2
 */
class HexFormatTest {

    @Test
    void testFormat() {
        Hash hash = new Sha512Hash("hello");
        HexFormat format = new HexFormat()
        String hex = format.format(hash)
        assertEquals hex, hash.toHex()
    }

    @Test
    void testFormatWithNullArgument() {
        HexFormat format = new HexFormat()
        assertThrows NullPointerException, { format.format(null) }
    }

}


