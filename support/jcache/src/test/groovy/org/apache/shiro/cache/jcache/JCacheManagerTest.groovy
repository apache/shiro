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
package org.apache.shiro.cache.jcache

import org.apache.shiro.cache.Cache
import org.apache.shiro.cache.CacheException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated

import static org.hamcrest.MatcherAssert.assertThat

import static org.hamcrest.Matchers.*

/**
 * Unit tests for {@link JCacheManager}.
 *
 * @since 1.9
 */
@Isolated
class JCacheManagerTest {

    @Test
    void invalidConfigFile() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.setCacheConfig("./invalid/location")
        def exception = expectThrows CacheException, { cacheManager.init() }
        assertThat exception.message, containsString("Could not load JCache configuration resource: ./invalid/location")
    }

    @Test
    void happyPath() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("foobar")
        assertThat cache, notNullValue()
        cache.put("Foo", "Bar")
        assertThat cache.get("Foo"), is("Bar")
    }

    @Test
    void sizeTest() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("size-test")
        assertThat cache, notNullValue()
        cache.put("one", "value")
        assertThat cache.size(), is(1)
    }

    @Test
    void clear() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("clear-test")
        assertThat cache, notNullValue()
        cache.put("one", "value")
        cache.clear()
        assertThat cache.get("one"), nullValue()
    }

    @Test
    void remove() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("remove-test")
        assertThat cache, notNullValue()
        cache.put("one", "value1")
        cache.put("two", "value2")
        cache.remove("one")
        assertThat cache.get("one"), nullValue()
        assertThat cache.get("two"), is("value2")
    }

    @Test
    void values() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("values-test")
        assertThat cache, notNullValue()
        cache.put("one", "value1")
        cache.put("two", "value2")
        assertThat cache.values(), containsInAnyOrder("value1", "value2")
    }

    @Test
    void keys() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("keys-test")
        assertThat cache, notNullValue()
        cache.put("one", "value1")
        cache.put("two", "value2")
        assertThat cache.keys(), containsInAnyOrder("one", "two")
    }

    @Test
    void putWithPrevious() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        Cache cache = cacheManager.getCache("putWithPrevious-test")
        assertThat cache, notNullValue()
        assertThat cache.put("one", "value1"), nullValue()
        assertThat cache.put("one", "value2"), is("value1")
        assertThat cache.get("one"), is("value2")
    }

    @Test
    void destroy() {
        JCacheManager cacheManager = new JCacheManager()
        cacheManager.init()
        assertThat cacheManager.cacheManagerImplicitlyCreated, is(true)
        Cache cache = cacheManager.getCache("destroy-test")
        assertThat cache.put("one", "value1"), nullValue()
        cacheManager.destroy()
        assertThat cacheManager.cacheManagerImplicitlyCreated, is(false)
        assertThat cacheManager.jCacheManager, nullValue()
    }

    static <T extends Throwable> T expectThrows(Class<T> exceptionClass, Closure closure) {
        try {
            closure.run()
        } catch (Throwable t) {
            if (exceptionClass.isAssignableFrom(t.getClass())) {
                return t as T
            }
            throw t
        }
        Assertions.fail("Expected ${exceptionClass.getName()} to be thrown");
        return null
    }
}
