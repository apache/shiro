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
import com.hazelcast.core.HazelcastInstance
import com.hazelcast.core.LifecycleService
import org.junit.Test

import static org.junit.Assert.*
import static org.mockito.Mockito.*

/**
 * Unit tests for {@link HazelcastCacheManager}.
 *
 * @since 1.3
 */
class HazelcastCacheManagerTest {

    @Test
    void testGetSetHazelcastInstance() {

        // given
        HazelcastInstance hc = mock(HazelcastInstance)
        def manager = new HazelcastCacheManager();

        // when
        manager.hazelcastInstance = hc

        // then
        assertSame hc, manager.hazelcastInstance
    }

    @Test
    void testCustomConfig() {

        // given
        Config config = mock(Config)
        def manager = new HazelcastCacheManager();

        // when
        manager.config = config

        // then
        assertSame config, manager.config
    }

    @Test
    void testImplicitlyCreated() {

        // given
        HazelcastInstance hazelcastInstance = mock(HazelcastInstance)

        HazelcastCacheManager manager = spy(HazelcastCacheManager);
        when(manager.createHazelcastInstance()).then(args -> hazelcastInstance)

        // when
        manager.init()

        // then
        assertTrue manager.implicitlyCreated
        manager.destroy()
    }

    @Test
    void testDestroy() {

        // given
        LifecycleService lifecycleService = mock(LifecycleService)

        HazelcastInstance hazelcastInstance = spy(HazelcastInstance)
        when(hazelcastInstance.getLifecycleService()).then(args -> lifecycleService)

        HazelcastCacheManager manager = spy(HazelcastCacheManager);
        when(manager.createHazelcastInstance()).then(args -> hazelcastInstance)


        // when
        manager.init()
        manager.destroy()

        // then
        assertFalse manager.implicitlyCreated
        assertNull manager.hazelcastInstance
        verify(hazelcastInstance).getLifecycleService()
        verify(manager).createHazelcastInstance()
    }

    @Test
    void testDestroyExplicit() {

        // given
        HazelcastInstance hazelcastInstance = mock(HazelcastInstance)
        HazelcastCacheManager manager = new HazelcastCacheManager()
        manager.hazelcastInstance = hazelcastInstance

        // when
        manager.init()
        manager.destroy()

        // then
        assertNotNull manager.hazelcastInstance
        assertFalse manager.implicitlyCreated
    }

    @Test
    void testUncleanShutdown() {

        // given
        LifecycleService lifecycleService = mock(LifecycleService)
        when(lifecycleService.shutdown()).thenThrow(new IllegalStateException())

        HazelcastInstance hazelcastInstance = mock(HazelcastInstance)
        when(hazelcastInstance.getLifecycleService()).then(args -> lifecycleService)

        HazelcastCacheManager manager = spy(HazelcastCacheManager);
        when(manager.createHazelcastInstance()).then(args -> hazelcastInstance)

        // when
        manager.init()
        manager.destroy()

        // then
        assertFalse manager.implicitlyCreated
        verify(lifecycleService).shutdown()
        verify(hazelcastInstance).getLifecycleService()
        verify(manager).createHazelcastInstance()
    }

}
