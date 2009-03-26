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
package org.apache.ki.cache.ehcache;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import net.sf.ehcache.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ki.cache.Cache;
import org.apache.ki.cache.CacheException;

/**
 * Ki {@link org.apache.ki.cache.Cache} implementation that wraps an {@link net.sf.ehcache.Ehcache} instance.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.2
 */
@SuppressWarnings("unchecked")
public class EhCache implements Cache {

    /** Private internal log instance. */
    private static final Log log = LogFactory.getLog(EhCache.class);

    /**
     * The wrapped Ehcache instance.
     */
    private net.sf.ehcache.Ehcache cache;

    /**
     * Constructs a new EhCache instance with the given cache.
     *
     * @param cache - delegate EhCache instance this Ki cache instance will wrap.
     */
    public EhCache(net.sf.ehcache.Cache cache) {
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
    public Object get(Object key) throws CacheException {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Getting object from cache [" + cache.getName() + "] for key [" + key + "]");
            }
            if (key == null) {
                return null;
            } else {
                Element element = cache.get(key);
                if (element == null) {
                    if (log.isTraceEnabled()) {
                        log.trace("Element for [" + key + "] is null.");
                    }
                    return null;
                } else {
                    return element.getObjectValue();
                }
            }
        }
        catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Puts an object into the cache.
     *
     * @param key   the key.
     * @param value the value.
     */
    public void put(Object key, Object value) throws CacheException {
        if (log.isTraceEnabled()) {
            log.trace("Putting object in cache [" + cache.getName() + "] for key [" + key + "]");
        }
        try {
            Element element = new Element(key, value);
            cache.put(element);
        }
        catch (Throwable t) {
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
    public void remove(Object key) throws CacheException {
        if (log.isTraceEnabled()) {
            log.trace("Removing object from cache [" + cache.getName() + "] for key [" + key + "]");
        }
        try {
            cache.remove(key);
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Removes all elements in the cache, but leaves the cache in a useable state.
     */
    public void clear() throws CacheException {
        if (log.isTraceEnabled()) {
            log.trace("Clearing all objects from cache [" + cache.getName() + "]");
        }
        try {
            cache.removeAll();
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public int size() {
        try {
            return cache.getSize();
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public Set keys() {
        try {
            List keys = cache.getKeys();
            if (keys != null && !keys.isEmpty()) {
                return Collections.unmodifiableSet(new LinkedHashSet(keys));
            } else {
                return Collections.EMPTY_SET;
            }
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public Set values() {
        try {
            List keys = cache.getKeys();
            if (keys != null && !keys.isEmpty()) {
                Set values = new LinkedHashSet(keys.size());
                for (Object key : keys) {
                    values.add(cache.get(key));
                }
                return Collections.unmodifiableSet(values);
            } else {
                return Collections.EMPTY_SET;
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
     *         number is unknown or cannot be calculated.
     */
    public long getMemoryUsage() {
        try {
            return cache.calculateInMemorySize();
        }
        catch (Throwable t) {
            return -1;
        }
    }

    /**
     * Returns the size (in bytes) that this EhCache's memory store is using (RAM), or <code>-1</code> if
     * that number is unknown or cannot be calculated.
     *
     * @return the size (in bytes) that this EhCache's memory store is using (RAM), or <code>-1</code> if
     *         that number is unknown or cannot be calculated.
     */
    public long getMemoryStoreSize() {
        try {
            return cache.getMemoryStoreSize();
        }
        catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Returns the size (in bytes) that this EhCache's disk store is consuming or <code>-1</code> if
     * that number is unknown or cannot be calculated.
     *
     * @return the size (in bytes) that this EhCache's disk store is consuming or <code>-1</code> if
     *         that number is unknown or cannot be calculated.
     */
    public long getDiskStoreSize() {
        try {
            return cache.getDiskStoreSize();
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Returns &quot;EhCache [&quot; + cache.getName() + &quot;]&quot;
     *
     * @return &quot;EhCache [&quot; + cache.getName() + &quot;]&quot;
     */
    public String toString() {
        return "EhCache [" + cache.getName() + "]";
    }
}
