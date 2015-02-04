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
package org.apache.shiro.codec

import org.apache.shiro.crypto.SecureRandomNumberGenerator

/**
 * Test cases for the {@link H64} implementation.
 */
class H64Test extends GroovyTestCase {

    void testNothing(){}

    public void testDefault() {
        byte[] orig = new SecureRandomNumberGenerator().nextBytes(6).bytes

        System.out.println("bytes: $orig");

        String encoded = H64.encodeToString(orig)
        System.out.println("encoded: $encoded");

        assertNotNull orig
    }
}
