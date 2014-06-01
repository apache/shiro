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

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

/**
 * A {@code CacheManager} implementation that does not perform any caching at all.  While at first glance this concept
 * might sound odd, it reflects the <a href="http://en.wikipedia.org/wiki/Null_Object_pattern">Null Object Design
 * Pattern</a>: other parts of Shiro or users' code do not need to perform null checks when interacting with Cache or
 * CacheManager instances, reducing code verbosity, enhancing readability, and reducing probability for certain bugs.
 *
 * @since 2.0
 */
public class DisabledCacheManager implements CacheManager {

    public static final DisabledCacheManager INSTANCE = new DisabledCacheManager();

    private static final Cache DISABLED_CACHE = new DisabledCache();

    @SuppressWarnings("unchecked")
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {
        return DISABLED_CACHE;
    }

    private static final class DisabledCache<K,V> implements Cache<K,V> {

        public V get(K key) throws CacheException {
            return null;
        }

        public V put(K key, V value) throws CacheException {
            return null;
        }

        public V remove(K key) throws CacheException {
            return null;
        }

        public void clear() throws CacheException {
        }

        public int size() {
            return 0;
        }

        public Set<K> keys() {
            return Collections.emptySet();
        }

        public Collection<V> values() {
            return Collections.emptySet();
        }
    }
}
