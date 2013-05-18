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

import org.apache.shiro.crypto.hash.Sha1Hash
import org.junit.Test
import static org.junit.Assert.*

/**
 * Unit tests for the {@link DefaultHashFormatFactory} implementation.
 *
 * @since 1.2
 */
class DefaultHashFormatFactoryTest {

    @Test
    void testDefaultInstance() {
        def factory = new DefaultHashFormatFactory()
        assertNotNull factory.formatClassNames
        assertTrue factory.formatClassNames.isEmpty()
        assertNotNull factory.searchPackages
        assertTrue factory.formatClassNames.isEmpty()
    }

    @Test
    void testNullArg() {
        def factory = new DefaultHashFormatFactory()
        assertNull factory.getInstance(null)
    }

    @Test
    void testNotFound() {
        def factory = new DefaultHashFormatFactory()
        assertNull factory.getInstance('foo')
    }

    @Test
    void testSetFormatClassNames() {
        def classNames = ['hex': HexFormat.class.name]
        def factory = new DefaultHashFormatFactory()
        factory.formatClassNames = classNames
        assertNotNull factory.formatClassNames
        assertEquals 1, factory.formatClassNames.size()
        assertEquals factory.formatClassNames['hex'], HexFormat.class.name
    }

    @Test
    void testGetInstanceWithConfiguredFormatClassName() {
        def classNames = ['anAlias': HexFormat.class.name]
        def factory = new DefaultHashFormatFactory(formatClassNames: classNames)
        def instance = factory.getInstance('anAlias')
        assertNotNull instance
        assertTrue instance instanceof HexFormat
    }

    @Test
    void testGetInstanceWithMcfFormattedString() {
        Shiro1CryptFormat format = new Shiro1CryptFormat()
        def formatted = format.format(new Sha1Hash("test"))

        def factory = new DefaultHashFormatFactory()

        def instance = factory.getInstance(formatted)

        assertNotNull instance
        assertTrue instance instanceof Shiro1CryptFormat
    }

    @Test
    void testAbsentFQCN() {
        def factory = new DefaultHashFormatFactory()
        def instance = factory.getInstance("com.foo.bar.some.random.MyHashFormat")
        assertNull instance
    }

    @Test
    void testPresentFQCN() {
        def factory = new DefaultHashFormatFactory()
        def instance = factory.getInstance(Shiro1CryptFormat.class.name)
        assertNotNull instance
        assertTrue instance instanceof Shiro1CryptFormat
    }

    @Test
    void testMcfFormattedArgument() {
        def factory = new DefaultHashFormatFactory()

        def hash = new Sha1Hash("test")
        def formatted = new Shiro1CryptFormat().format(hash)

        def instance = factory.getInstance(formatted)

        assertNotNull instance
        assertTrue instance instanceof Shiro1CryptFormat
    }

    @Test
    void testSearchPackages() {
        def factory = new DefaultHashFormatFactory()
        factory.searchPackages = ['org.apache.shiro.crypto.hash.format']

        //find the test class 'ToStringHashFormat'
        def instance = factory.getInstance('toString')

        assertNotNull instance
        assertTrue instance instanceof ToStringHashFormat
    }

    @Test
    void testSearchPackagesWithoutMatch() {
        def factory = new DefaultHashFormatFactory()
        factory.searchPackages = ['com.foo']

        assertNull factory.getInstance('bar')
    }

    @Test
    void testWithInvalidHashFormatImplementation() {
        def factory = new DefaultHashFormatFactory()
        try {
            factory.getInstance("java.lang.Integer")
            fail "Call should have resulted in an IllegalArgumentException"
        } catch (IllegalArgumentException expected) {
        }

    }
}
