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

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.*

/**
 * Unit tests for the {@link ProvidedHashFormat} implementation.
 *
 * @since 1.2
 */
class ProvidedHashFormatTest {

    @Test
    void testDefaults() {
        def set = ProvidedHashFormat.values() as Set
        assertEquals 4, set.size()
        assertTrue set.contains(ProvidedHashFormat.HEX)
        assertTrue set.contains(ProvidedHashFormat.BASE64)
        assertTrue set.contains(ProvidedHashFormat.SHIRO1)
    }

    @Test
    void testByIdWithNullArg() {
        assertNull ProvidedHashFormat.byId(null)
    }

}
