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
import org.apache.shiro.crypto.hash.format.Shiro2CryptFormat
import org.apache.shiro.lang.util.SimpleByteSource
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.Executable

import static org.junit.jupiter.api.Assertions.*

class Argon2HashTest {

    private static final TEST_PASSWORD = "secret#shiro,password;Jo8opech";
    private static final TEST_PASSWORD_BS = new SimpleByteSource(TEST_PASSWORD)

    @Test
    void testArgon2Hash() {
        // given
        def shiro2Format = '$shiro2$argon2id$v=19$m=4096,t=3,p=4$MTIzNDU2Nzg5MDEyMzQ1Ng$bjcHqfb0LPHyS13eVaNcBga9LF12I3k34H5ULt2gyoI'
        def expectedPassword = new SimpleByteSource('secret#shiro,password;Jo8opech')

        // when
        def hash = new Shiro2CryptFormat().parse(shiro2Format) as Argon2Hash;
        System.out.println("Hash: " + hash)
        def matchesPassword = hash.matchesPassword expectedPassword;

        // then
        assertEquals Argon2Parameters.ARGON2_VERSION_13, hash.argonVersion
        assertEquals 3, hash.iterations
        assertEquals 4096, hash.memoryKiB
        assertEquals 4, hash.parallelism
        assertTrue matchesPassword
    }

    @Test
    void testArgon2HashShiro1Format() {
        // given
        def shiro1Format = '$shiro1$argon2id$v=19$t=2,m=131072,p=4$7858qTJTreh61AzFV2XMOw==$lLzl2VNNbyFcuJo0Hp7JQpguKCDoQwxo91AWobcHzeo='

        // when
        def thrownException = assertThrows(
                UnsupportedOperationException,
                { new Shiro1CryptFormat().parse shiro1Format } as Executable
        )

        // then
        assertTrue thrownException.getMessage().contains("shiro1")
    }

    @Test
    void testFromStringMatchesPw() {
        // when
        def argon2String = '$argon2id$v=19$m=4096,t=3,p=4$MTIzNDU2Nzg5MDEyMzQ1Ng$bjcHqfb0LPHyS13eVaNcBga9LF12I3k34H5ULt2gyoI'
        // for testing recreated salt and data parts, as the parameter order could change.
        def saltDataPart = argon2String.substring(30)

        // when
        def argon2Hash = Argon2Hash.fromString argon2String
        def recreatedSaltDataPart = argon2Hash.formatToCryptString().substring(30)

        // then
        assertTrue argon2Hash.matchesPassword(TEST_PASSWORD_BS)
        // we can only test the salt + data parts, as
        // the parameter order could change.
        assertEquals saltDataPart, recreatedSaltDataPart
    }

}
