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
package org.apache.shiro.cache;

import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.LifecycleUtils;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


/**
 * Default memory-only based {@link CacheManager CacheManager} implementation usable in production environments.
 * <p/>
 * This implementation does not offer any enterprise-level features such as cache coherency, optimistic locking,
 * failover or other similar features.  It relies on memory-based {@link SoftHashMapCache} instances to ensure there
 * are no memory leaks.  For more enterprise features, consider using an
 * {@code org.apache.shiro.cache.ehcache.EhCacheManager} or other similar implementation that wraps an enterprise-grade
 * Caching solution.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class DefaultCacheManager implements CacheManager, Destroyable {

    /**
     * Retains all Cache objects maintained by this cache manager.
     */
    private final ConcurrentMap<String, Cache> caches = new ConcurrentHashMap<String, Cache>();

    public Cache getCache(String name) throws CacheException {
        if (name == null) {
            throw new CacheException("Cache name cannot be null.");
        }

        Cache cache;

        cache = caches.get(name);
        if (cache == null) {
            cache = new SoftHashMapCache(name);
            Cache existing = caches.putIfAbsent(name, cache);
            if (existing != null) {
                cache = existing;
            }
        }

        return cache;
    }

    public void destroy() throws Exception {
        while( !caches.isEmpty() ) {
            for (Cache cache : caches.values()) {
                LifecycleUtils.destroy(cache);
            }
            caches.clear();
        }
    }
}
