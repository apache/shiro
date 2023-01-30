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
package org.apache.shiro.cache.jcache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.spi.CachingProvider;
import java.net.URL;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Shiro {@code CacheManager} implementation utilizing JCache for all cache functionality.
 * <p/>
 * This class can {@link #setCacheManager(javax.cache.CacheManager) accept} a manually configured
 * {@link javax.cache.CacheManager javax.cache.CacheManager} instance,
 * a {@code cacheConfig} URI can be specified, or a call to {@link CachingProvider#getCacheManager()} will be used.
 * <p/>
 * This implementation requires a JCache implementation available on the classpath.
 * <p/>
 * @since 1.9
 */
public class JCacheManager implements CacheManager, Initializable, Destroyable {

    /**
     * This class's private log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(JCacheManager.class);

    private javax.cache.CacheManager jCacheManager;

    private String cacheConfig;

    /**
     * Indicates if the CacheManager instance was implicitly/automatically created by this instance, indicating that
     * it should be automatically cleaned up as well on shutdown.
     */
    private boolean cacheManagerImplicitlyCreated = false;

    @Override
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {

        javax.cache.Cache<K, V> cache = ensureCacheManager().getCache(name);

        if (cache == null) {
            synchronized (this) {
                cache = ensureCacheManager().getCache(name);
                if (cache == null) {
                    log.debug("Cache with name '{}' does not yet exist.  Creating now.", name);
                    cache = ensureCacheManager().createCache(name, new MutableConfiguration<>());
                    log.debug("Added JCache named [{}]", name);
                } else {
                    log.debug("Using existing JCache named [{}]", cache.getName());
                }
            }
        }

        return new JCache<>(cache);
    }

    /**
     * Initializes this instance.
     * <p/>
     * If a CacheManager has been
     * explicitly set (e.g. via Dependency Injection or programmatically) prior to calling this
     * method, this method does nothing.
     * <p/>
     * Because Shiro cannot use the failsafe defaults (fail-safe expunges cached objects after 2 minutes,
     * something not desirable for Shiro sessions), this class manages an internal default configuration for
     * this case.
     *
     * @throws org.apache.shiro.cache.CacheException
     *          if there are any CacheExceptions thrown by JCache.
     */
    public final void init() throws CacheException {
        ensureCacheManager();
    }

    private javax.cache.CacheManager ensureCacheManager() {
        try {
            if (this.jCacheManager == null) {
                log.debug("cacheManager property not set.  Constructing CacheManager instance... ");
                CachingProvider cachingProvider = Caching.getCachingProvider();

                if (StringUtils.hasText(cacheConfig)) {

                    URL config = getClass().getResource(cacheConfig);
                    if (config == null) {
                        throw new IllegalArgumentException("Could not load JCache configuration resource: " + cacheConfig);
                    }

                    this.jCacheManager = cachingProvider.getCacheManager(config.toURI(), getClass().getClassLoader());
                } else {
                    this.jCacheManager = cachingProvider.getCacheManager();
                }

                cacheManagerImplicitlyCreated = true;
                log.debug("implicit cacheManager created successfully.");
            }
            return this.jCacheManager;
        } catch (Exception e) {
            throw new CacheException(e);
        }
    }

    /**
     * Shuts-down the wrapped JCache CacheManager <b>only if implicitly created</b>.
     * <p/>
     * If another component injected
     * a non-null CacheManager into this instance before calling {@link #init() init}, this instance expects that same
     * component to also destroy the CacheManager instance, and it will not attempt to do so.
     */
    public void destroy() {
        if (cacheManagerImplicitlyCreated) {
            try {
                jCacheManager.close();
            } catch (Throwable t) {
                    log.warn("Unable to cleanly shutdown implicitly created CacheManager instance. Ignoring (shutting down)...", t);
            } finally {
                this.jCacheManager = null;
                this.cacheManagerImplicitlyCreated = false;
            }
        }
    }

    public String getCacheConfig() {
        return cacheConfig;
    }

    public void setCacheConfig(String jCacheConfig) {
        this.cacheConfig = jCacheConfig;
    }

    public javax.cache.CacheManager getCacheManager() {
        return jCacheManager;
    }

    public void setCacheManager(javax.cache.CacheManager jCacheManager) {
        this.jCacheManager = jCacheManager;
    }

    static class JCache<K,V> implements Cache<K,V> {

        private final javax.cache.Cache<K,V> cache;

        JCache(javax.cache.Cache<K,V> cache) {
            this.cache = cache;
        }
        /**
         * Gets a value of an element which matches the given key.
         *
         * @param key the key of the element to return.
         * @return The value placed into the cache with an earlier put, or null if not found or expired
         */
        @Override
        public V get(K key) throws CacheException {
            try {
                log.trace("Getting object from cache [{}] for key [{}]", cache.getName(), key);
                if (key == null) {
                    return null;
                } else {
                    V element = cache.get(key);
                    if (element == null) {
                        log.trace("Element for [{}] is null.", key);
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
            log.trace("Putting object in cache [{}] for key [{}]", cache.getName(), key);
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
            log.trace("Removing object from cache [{}] for key [{}]", cache.getName(), key);
            try {
                return cache.getAndRemove(key);
            } catch (Throwable t) {
                throw new CacheException(t);
            }
        }

        /**
         * Removes all elements in the cache, but leaves the cache in a useable state.
         */
        public void clear() throws CacheException {
            log.trace("Clearing all objects from cache [{}]", cache.getName());
            try {
                cache.removeAll();
            } catch (Throwable t) {
                throw new CacheException(t);
            }
        }

        public int size() {
            return (int) toStream(cache.iterator()).count();
        }

        @Override
        public Set<K> keys() {
            return toStream(cache.iterator())
                    .map(javax.cache.Cache.Entry::getKey)
                    .collect(Collectors.toSet());
        }

        @Override
        public Collection<V> values() {
            return toStream(cache.iterator())
                    .map(javax.cache.Cache.Entry::getValue)
                    .collect(Collectors.toSet());
        }

        private Stream<javax.cache.Cache.Entry<K, V>> toStream(Iterator<javax.cache.Cache.Entry<K, V>> iterator) {
            return StreamSupport.stream(Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED), false);
        }
    }
}
