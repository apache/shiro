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
package org.jsecurity.cache;

import java.util.*;

/**
 * An implementation of the JSecurity {@link Cache} interface that uses a
 * {@link Hashtable} to store cached objects.  This implementation is only suitable for
 * development/testing use.  A more robust caching solution should be used for production
 * systems such as the {@link org.jsecurity.cache.ehcache.EhCacheManager}
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.2
 */
@SuppressWarnings("unchecked")
public class HashtableCache implements Cache {

    /**
     * The underlying hashtable.
     */
    private final Map hashtable = new Hashtable();

    /**
     * The name of this cache.
     */
    private final String name;

    /**
     * Creates a new cache with the given name.
     *
     * @param name the name of this cache.
     */
    public HashtableCache(String name) {
        this.name = name;
    }

    public Object get(Object key) throws CacheException {
        return hashtable.get(key);
    }

    public void put(Object key, Object value) throws CacheException {
        hashtable.put(key, value);
    }

    public void remove(Object key) throws CacheException {
        hashtable.remove(key);
    }

    public void clear() throws CacheException {
        hashtable.clear();
    }

    public int size() {
        return hashtable.size();
    }

    public Set keys() {
        if (!hashtable.isEmpty()) {
            return Collections.unmodifiableSet(hashtable.keySet());
        } else {
            return Collections.EMPTY_SET;
        }
    }

    public Set values() {
        if (!hashtable.isEmpty()) {
            Collection values = hashtable.values();
            if (values instanceof Set) {
                return Collections.unmodifiableSet((Set) values);
            } else {
                return Collections.unmodifiableSet(new LinkedHashSet(values));
            }
        } else {
            return Collections.EMPTY_SET;
        }
    }

    public String toString() {
        return "HashtableCache [" + name + "]";
    }
}