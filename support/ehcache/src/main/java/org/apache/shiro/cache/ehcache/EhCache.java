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

import java.util.LinkedList;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


/**
 * Shiro {@link org.apache.shiro.cache.Cache} implementation that wraps an {@link org.ehcache.core.Ehcache} instance.
 *
 * @param <K> K
 * @param <V> V
 * @since 0.2
 */
public class EhCache<K, V> implements Cache<K, V> {

    /**
     * Private internal log instance.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EhCache.class);

    /**
     * The wrapped Ehcache instance.
     */
    private org.ehcache.Cache<K, V> cache;

    /**
     * Constructs a new EhCache instance with the given cache.
     *
     * @param cache - delegate EhCache instance this Shiro cache instance will wrap.
     */
    public EhCache(org.ehcache.Cache<K, V> cache) {
        if (cache == null) {
            throw new IllegalArgumentException("Cache argument cannot be null.");
        }
        this.cache = cache;
    }

    /**
     * Gets a value of an element which matches the given key.
     *
     * @param key the key of the element to return.
     * @return The value placed into the cache with an earlier put, or null if not found or expired
     */
    public V get(K key) throws CacheException {
        try {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Getting object from cache [{}] for key [{}]", cache, key);
            }
            if (key == null) {
                return null;
            } else {
                V element = cache.get(key);
                if (element == null) {
                    if (LOGGER.isTraceEnabled()) {
                        LOGGER.trace("Element for [{}] is null.", key);
                    }
                    return null;
                } else {
                    return element;
                }
            }
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Puts an object into the cache.
     *
     * @param key   the key.
     * @param value the value.
     */
    public V put(K key, V value) throws CacheException {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Putting object in cache [{}] for key [{}]", cache, key);
        }
        try {
            V previous = get(key);
            cache.put(key, value);
            return previous;
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Removes the element which matches the key.
     *
     * <p>If no element matches, nothing is removed and no Exception is thrown.</p>
     *
     * @param key the key of the element to remove
     */
    public V remove(K key) throws CacheException {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Removing object from cache [{}] for key [{}]", cache, key);
        }
        try {
            V previous = get(key);
            cache.remove(key);
            return previous;
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Removes all elements in the cache, but leaves the cache in a usable state.
     */
    public void clear() throws CacheException {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Clearing all objects from cache [{}]", cache);
        }
        try {
            cache.removeAll(keys());
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public int size() {
        try {
            int size = 0;
            for (org.ehcache.Cache.Entry<K, V> ignored : cache) {
                size++;
            }
            return size;
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public Set<K> keys() {
        try {
            List<K> keys = new LinkedList<>();
            for (org.ehcache.Cache.Entry<K, V> entry : cache) {
                keys.add(entry.getKey());
            }

            if (!isEmpty(keys)) {
                return Collections.unmodifiableSet(new LinkedHashSet<>(keys));
            } else {
                return Collections.emptySet();
            }
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public Collection<V> values() {
        try {
            Set<K> keys = keys();
            if (!isEmpty(keys)) {
                List<V> values = new ArrayList<>(keys.size());
                for (K key : keys) {
                    V value = get(key);
                    if (value != null) {
                        values.add(value);
                    }
                }
                return Collections.unmodifiableList(values);
            } else {
                return Collections.emptyList();
            }
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Returns the size (in bytes) that this EhCache is using in memory (RAM), or <code>-1</code> if that
     * number is unknown or cannot be calculated.
     *
     * @return the size (in bytes) that this EhCache is using in memory (RAM), or <code>-1</code> if that
     * number is unknown or cannot be calculated.
     */
    public long getMemoryUsage() {
        return -1;
    }

    /**
     * Returns the size (in bytes) that this EhCache's memory store is using (RAM), or <code>-1</code> if
     * that number is unknown or cannot be calculated.
     *
     * @return the size (in bytes) that this EhCache's memory store is using (RAM), or <code>-1</code> if
     * that number is unknown or cannot be calculated.
     */
    public long getMemoryStoreSize() {
        return -1;
    }

    /**
     * Returns the size (in bytes) that this EhCache's disk store is consuming or <code>-1</code> if
     * that number is unknown or cannot be calculated.
     *
     * @return the size (in bytes) that this EhCache's disk store is consuming or <code>-1</code> if
     * that number is unknown or cannot be calculated.
     */
    public long getDiskStoreSize() {
        return -1;
    }

    /**
     * Returns &quot;EhCache [&quot; + cache + &quot;]&quot;
     *
     * @return &quot;EhCache [&quot; + cache + &quot;]&quot;
     */
    public String toString() {
        return "EhCache [" + cache + "]";
    }

    //////////////////////////
    // From CollectionUtils //
    //////////////////////////
    // CollectionUtils cannot be removed from shiro-core until 2.0 as it has a dependency on PrincipalCollection

    private static boolean isEmpty(Collection<?> c) {
        return c == null || c.isEmpty();
    }
}
