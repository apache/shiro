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

import com.hazelcast.config.Config
import com.hazelcast.core.Hazelcast
import com.hazelcast.core.HazelcastInstance
import com.hazelcast.core.IMap
import com.hazelcast.core.LifecycleService
import org.apache.shiro.cache.MapCache
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.same
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.*

/**
 * Unit tests for {@link HazelcastCacheManager}.  Uses PowerMock to mock Hazelcast's static method calls.
 *
 * @since 1.3
 */
@RunWith(PowerMockRunner)
@PrepareForTest(Hazelcast)
class HazelcastCacheManagerTest {

    @Test
    void testGetSetHazelcastInstance() {
        def hc = createStrictMock(HazelcastInstance)
        def manager = new HazelcastCacheManager();
        manager.hazelcastInstance = hc

        replay hc

        assertSame hc, manager.hazelcastInstance

        verify hc
    }

    @Test
    void testInit() {

        mockStatic(Hazelcast)
        //create a mock instead of starting a networked node:
        def hc = createStrictMock(HazelcastInstance)

        expect(Hazelcast.newHazelcastInstance(null)).andReturn(hc)

        replay Hazelcast, hc

        def manager = new HazelcastCacheManager()

        try {
            manager.init()

            assertNull manager.config
            assertSame hc, manager.hazelcastInstance
            assertTrue manager.implicitlyCreated
        } finally {
            verify Hazelcast, hc
        }
    }

    @Test
    void testDestroy() {

        mockStatic Hazelcast
        def hc = createStrictMock(HazelcastInstance)
        def lcService = createStrictMock(LifecycleService)

        expect(Hazelcast.newHazelcastInstance(null)).andReturn(hc)
        expect(hc.getLifecycleService()).andReturn(lcService)
        lcService.shutdown()

        replay Hazelcast, hc, lcService

        def manager = new HazelcastCacheManager()
        manager.init() //force implicit creation

        manager.destroy()

        assertNull manager.hazelcastInstance
        assertFalse manager.implicitlyCreated

        verify Hazelcast, hc, lcService
    }

    @Test
    void testDestroyWithThrowable() {

        mockStatic Hazelcast
        def hc = createStrictMock(HazelcastInstance)
        def lcService = createStrictMock(LifecycleService)

        expect(Hazelcast.newHazelcastInstance(null)).andReturn(hc)
        expect(hc.getLifecycleService()).andReturn(lcService)
        lcService.shutdown()
        expectLastCall().andThrow(new IllegalStateException())

        replay Hazelcast, hc, lcService

        def manager = new HazelcastCacheManager()
        manager.init() //force implicit creation

        manager.destroy()

        assertNull manager.hazelcastInstance
        assertFalse manager.implicitlyCreated

        verify Hazelcast, hc, lcService
    }


    @Test
    void testGetCache() {

        mockStatic Hazelcast
        def hc = createStrictMock(HazelcastInstance)
        def hcMap = createStrictMock(IMap)

        expect(Hazelcast.newHazelcastInstance(null)).andReturn(hc)
        expect(hc.getMap("foo")).andReturn(hcMap)

        replay Hazelcast, hc, hcMap

        try {
            def manager = new HazelcastCacheManager()
            def cache = manager.getCache("foo")

            assertNotNull cache
            assertTrue cache instanceof MapCache
            assertNotNull cache.map
            assertTrue cache.map instanceof IMap
        } finally {
            verify Hazelcast, hc, hcMap
        }
    }

    @Test
    void testCustomConfig() {

        mockStatic Hazelcast

        def hc = createStrictMock(HazelcastInstance)
        def config = createStrictMock(Config)

        expect(Hazelcast.newHazelcastInstance(same(config))).andReturn(hc)

        replay Hazelcast, config

        def manager = new HazelcastCacheManager()
        manager.config = config

        manager.init()

        assertSame config, manager.config
        assertSame hc, manager.hazelcastInstance

        verify Hazelcast, config
    }


}
