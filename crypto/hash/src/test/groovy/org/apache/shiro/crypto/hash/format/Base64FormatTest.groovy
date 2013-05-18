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
import org.apache.shiro.crypto.hash.Sha1Hash
import org.junit.Test
import static org.junit.Assert.*

/**
 * Unit tests for the {@link Base64Format} implementation.
 *
 * @since 1.2
 */
class Base64FormatTest {

    @Test
    void testFormat() {
        Hash hash = new Sha1Hash("hello");
        Base64Format format = new Base64Format()
        String base64 = format.format(hash)
        assertEquals base64, hash.toBase64()
    }

    @Test
    void testFormatWithNullArgument() {
        Base64Format format = new Base64Format()
        assertNull format.format(null)
    }

}
