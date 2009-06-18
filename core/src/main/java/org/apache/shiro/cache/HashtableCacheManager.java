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

/**
 * A {@link CacheManager} that returns {@link HashtableCache} caches.
 * <p/>
 * This implementation is only suitable for development/testing as hashtable-based caches are prone to
 * potential memory leaks if objects are not explicitly removed from these caches over time.  If you are configuring
 * your own cache manager, consider using a production quality
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.2
 */
public class HashtableCacheManager implements CacheManager {

    /**
     * Builds a new {@link HashtableCache} with the given name.
     *
     * @param cacheName the name of the new cache to create.
     * @return a new cache.
     */
    public Cache getCache(String cacheName) {
        return new HashtableCache(cacheName);
    }
}