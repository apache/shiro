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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TODO - Class JavaDoc
 *
 * @since May 11, 2010 12:41:38 PM
 */
public class EhCacheManagerTest {

    private EhCacheManager cacheManager;

    @BeforeEach
    public void setUp() {
        cacheManager = new EhCacheManager();
    }

    @AfterEach
    public void tearDown() {
        LifecycleUtils.destroy(cacheManager);
    }

    @Test
    void testCacheManagerCreationDuringInit() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNull();
        cacheManager.init();
        //now assert that an internal CacheManager has been created:
        ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNotNull();
    }

    @Test
    void testLazyCacheManagerCreationWithoutCallingInit() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNull();

        //don't call init here - the ehcache CacheManager should be lazily created
        //because of the default Shiro ehcache.xml file in the classpath.  Just acquire a cache:
        Cache<String, String> cache = cacheManager.getCache("test");

        //now assert that an internal CacheManager has been created:
        ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNotNull();

        assertThat(cache).isNotNull();
        cache.put("hello", "world");
        String value = cache.get("hello");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo("world");
    }

    @Test
    void testRemove() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNull();

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNotNull();

        assertThat(cache).isNotNull();
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo("world");
        assertThat(cache.get("hello2")).isEqualTo("world2");
        assertThat(cache.size()).isEqualTo(2);

        assertThat(cache.remove("hello")).isEqualTo("world");
        assertThat(cache.size()).isEqualTo(1);
        assertThat(cache.remove("hello2")).isEqualTo("world2");
        assertThat(cache.size()).isEqualTo(0);

        assertThat(cache.remove("blah")).isNull();
    }

    @Test
    void testClear() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNull();

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNotNull();

        assertThat(cache).isNotNull();
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo("world");
        assertThat(cache.get("hello2")).isEqualTo("world2");
        assertThat(cache.size()).isEqualTo(2);

        cache.clear();
        assertThat(cache.size()).isEqualTo(0);

        assertThat(cache.get("hello")).isNull();
    }

    @Test
    void testKeys() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNull();

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNotNull();

        assertThat(cache).isNotNull();
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo("world");
        assertThat(cache.get("hello2")).isEqualTo("world2");
        assertThat(cache.size()).isEqualTo(2);

        Set<String> keys = cache.keys();
        assertThat(keys).hasSize(2);
        assertThat(keys).contains("hello");
        assertThat(keys).contains("hello2");

        assertThat(cache.remove("hello")).isEqualTo("world");
        assertThat(cache.size()).isEqualTo(1);

        keys = cache.keys();
        assertThat(keys).hasSize(1);
        assertThat(keys).contains("hello2");

        assertThat(cache.remove("blah")).isNull();
    }

    @Test
    void testValues() {
        net.sf.ehcache.CacheManager ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNull();

        Cache<String, String> cache = cacheManager.getCache("test");

        ehCacheManager = cacheManager.getCacheManager();
        assertThat(ehCacheManager).isNotNull();

        assertThat(cache).isNotNull();
        cache.put("hello", "world");
        cache.put("hello2", "world2");
        String value = cache.get("hello");
        assertThat(value).isNotNull();
        assertThat(value).isEqualTo("world");
        assertThat(cache.get("hello2")).isEqualTo("world2");
        assertThat(cache.size()).isEqualTo(2);

        Collection<String> values = cache.values();
        assertThat(values).hasSize(2);
        assertThat(values).contains("world");
        assertThat(values).contains("world2");

        assertThat(cache.remove("hello")).isEqualTo("world");
        assertThat(cache.size()).isEqualTo(1);

        values = cache.values();
        assertThat(values).hasSize(1);
        assertThat(values).contains("world2");

        assertThat(cache.remove("blah")).isNull();
    }

}
