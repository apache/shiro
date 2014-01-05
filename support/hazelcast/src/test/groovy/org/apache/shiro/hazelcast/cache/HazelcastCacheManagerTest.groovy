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
package org.apache.shiro.hazelcast.cache

import com.hazelcast.core.HazelcastInstance
import com.hazelcast.core.IMap
import org.apache.shiro.cache.CacheException
import org.apache.shiro.cache.MapCache
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for {@link HazelcastCacheManager}.  Uses PowerMock to mock Hazelcast's static method calls.
 *
 * @since 1.3
 */
class HazelcastCacheManagerTest {

    HazelcastCacheManager manager

    @Before
    void setUp() {
        manager = new HazelcastCacheManager()
    }

    @Test
    void testInitWithoutHazelcastInstance() {
        try {
            manager.init()
            fail("CacheException expected.")
        } catch (CacheException ce) {
            assertEquals("The " + HazelcastCacheManager.class.getName() + " instance must be configured with a HazelcastInstance instance before it can be used.", ce.getMessage())
        }
    }

    @Test
    void testInit() {
        def hc = createStrictMock(HazelcastInstance)

        replay hc

        manager.hazelcastInstance = hc

        verify hc
    }

    @Test
    void testSetHazelcastInstance() {
        def hc = createStrictMock(HazelcastInstance)

        replay hc

        manager.hazelcastInstance = hc
        assertSame hc, manager.hazelcastInstance

        verify hc
    }

    @Test
    void testGetSetHazelcastInstance() {
        def hc = createStrictMock(HazelcastInstance)

        manager.hazelcastInstance = hc

        replay hc

        assertSame hc, manager.hazelcastInstance

        verify hc
    }

    @Test
    void testGetCacheWithoutHazelcastInstance() {
        try {
            manager.getCache('foo')
            fail("CacheException expected.")
        } catch (CacheException ce) {
            assertEquals("The " + HazelcastCacheManager.class.getName() + " instance must be configured with a HazelcastInstance instance before it can be used.", ce.getMessage())
        }
    }

    @Test
    void testGetCache() {

        def hc = createStrictMock(HazelcastInstance)
        def hcMap = createStrictMock(IMap)

        expect(hc.getMap(eq('foo'))).andReturn(hcMap)

        replay hc, hcMap

        try {
            manager.hazelcastInstance = hc
            def cache = manager.getCache('foo')

            assertNotNull cache
            assertTrue cache instanceof MapCache
            assertNotNull cache.map
            assertSame hcMap, cache.map
        } finally {
            verify hc, hcMap
        }
    }
}
