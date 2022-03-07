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
package org.apache.shiro.cache.ehcache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.lang.util.LifecycleUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

import java.util.Collection;
import java.util.Set;

/**
 * TODO - Class JavaDoc
 *
 * @since May 11, 2010 12:41:38 PM
 */
public class EhCacheManagerTest {

    private EhCacheManager cacheManager;

    @Before
    public void setUp() {
        cacheManager = new EhCacheManager();
    }

    @After
    public void tearDown() {
        LifecycleUtils.destroy(cacheManager);
    }

    @Test
    public void testCacheManagerCreationDuringInit() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertNull(ehCacheManager);
        cacheManager.init();
        //now assert that an internal CacheManager has been created:
        ehCacheManager = cacheManager.getCacheManager();
        assertNotNull(ehCacheManager);
    }

    @Test
    public void testLazyCacheManagerCreationWithoutCallingInit() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertNull(ehCacheManager);

        //don't call init here - the ehcache CacheManager should be lazily created
        //because of the default Shiro ehcache.xml file in the classpath.  Just acquire a cache:
        Cache<String, String> cache = cacheManager.getCache("test");

        //now assert that an internal CacheManager has been created:
        ehCacheManager = cacheManager.getCacheManager();
        assertNotNull(ehCacheManager);

        assertNotNull(cache);
        cache.put("hello", "world");
        String value = cache.get("hello");
        assertNotNull(value);
        assertEquals(value, "world");
    }

    @Test
    public void testRemove() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertNull(ehCacheManager);

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertNotNull(ehCacheManager);

        assertNotNull(cache);
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertNotNull(value);
        assertEquals(value, "world");
        assertEquals("world2", cache.get("hello2"));
        assertEquals(2, cache.size());

        assertEquals("world", cache.remove("hello"));
        assertEquals(1, cache.size());
        assertEquals("world2", cache.remove("hello2"));
        assertEquals(0, cache.size());

        assertNull(cache.remove("blah"));
    }

    @Test
    public void testClear() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertNull(ehCacheManager);

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertNotNull(ehCacheManager);

        assertNotNull(cache);
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertNotNull(value);
        assertEquals(value, "world");
        assertEquals("world2", cache.get("hello2"));
        assertEquals(2, cache.size());

        cache.clear();
        assertEquals(0, cache.size());

        assertNull(cache.get("hello"));
    }

    @Test
    public void testKeys() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertNull(ehCacheManager);

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertNotNull(ehCacheManager);

        assertNotNull(cache);
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertNotNull(value);
        assertEquals(value, "world");
        assertEquals("world2", cache.get("hello2"));
        assertEquals(2, cache.size());

        Set<String> keys = cache.keys();
        assertEquals(2, keys.size());
        assertTrue(keys.contains("hello"));
        assertTrue(keys.contains("hello2"));

        assertEquals("world", cache.remove("hello"));
        assertEquals(1, cache.size());

        keys = cache.keys();
        assertEquals(1, keys.size());
        assertTrue(keys.contains("hello2"));

        assertNull(cache.remove("blah"));
    }

    @Test
    public void testValues() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertNull(ehCacheManager);

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertNotNull(ehCacheManager);

        assertNotNull(cache);
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertNotNull(value);
        assertEquals(value, "world");
        assertEquals("world2", cache.get("hello2"));
        assertEquals(2, cache.size());

        Collection<String> values = cache.values();
        assertEquals(2, values.size());
        assertTrue(values.contains("world"));
        assertTrue(values.contains("world2"));

        assertEquals("world", cache.remove("hello"));
        assertEquals(1, cache.size());

        values = cache.values();
        assertEquals(1, values.size());
        assertTrue(values.contains("world2"));

        assertNull(cache.remove("blah"));
    }

}
