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
package org.apache.shiro.event.support

import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.createStrictMock
import static org.junit.Assert.*

/**
 * @since 1.3
 */
class EventListenerComparatorTest {

    EventListenerComparator comparator

    @Before
    void setUp() {
        comparator = new EventListenerComparator()
    }

    @Test
    void testANull() {
        def result = comparator.compare(null, createStrictMock(EventListener))
        assertEquals(-1, result)
    }

    @Test
    void testBNull() {
        def result = comparator.compare(createStrictMock(EventListener), null)
        assertEquals 1, result
    }

    @Test
    void testBothNull() {
        assertEquals 0, comparator.compare(null, null)
    }

    @Test
    void testBothSame() {
        def mock = createStrictMock(EventListener)
        assertEquals 0, comparator.compare(mock, mock)
    }

    @Test
    void testBothEventListener() {
        def a = createStrictMock(EventListener)
        def b = createStrictMock(EventListener)
        assertEquals 0, comparator.compare(a, b)
    }

    @Test
    void testATypedListenerBNormalListener() {
        def a = createStrictMock(TypedEventListener)
        def b = createStrictMock(EventListener)
        assertEquals(-1, comparator.compare(a, b))
    }

    @Test
    void testANormalBTypedListener() {
        def a = createStrictMock(EventListener)
        def b = createStrictMock(TypedEventListener)
        assertEquals 1, comparator.compare(a, b)
    }
}
