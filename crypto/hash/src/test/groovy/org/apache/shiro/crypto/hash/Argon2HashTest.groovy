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

import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat
import org.apache.shiro.lang.util.SimpleByteSource
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertTrue

class Argon2HashTest {

    @Test
    void testArgon2Hash() {
        // given
        def shiro1Format = '$shiro1$argon2id$2,131072,4$7858qTJTreh61AzFV2XMOw==$lLzl2VNNbyFcuJo0Hp7JQpguKCDoQwxo91AWobcHzeo='
        def expectedPassword = new SimpleByteSource('secret#shiro,password;Jo8opech')

        // when
        def hash = new Shiro1CryptFormat().parse shiro1Format;
        def matchesPassword = hash.matchesPassword expectedPassword;

        // then
        assertTrue matchesPassword
    }

}
