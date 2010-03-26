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

import java.util.*;

/**
 * A <code>MapCache</code> is a {@link Cache Cache} implementation that uses a backing {@link Map} instance to store
 * and retrieve cached data.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class MapCache implements Cache {

    /**
     * Backing instance.
     */
    private final Map map;

    /**
     * The name of this cache.
     */
    private final String name;

    public MapCache(String name, Map backingMap) {
        if (name == null) {
            throw new IllegalArgumentException("Cache name cannot be null.");
        }
        if (backingMap == null) {
            throw new IllegalArgumentException("Backing map cannot be null.");
        }
        this.name = name;
        this.map = backingMap;
    }

    public Object get(Object key) throws CacheException {
        return map.get(key);
    }

    @SuppressWarnings({"unchecked"})
    public void put(Object key, Object value) throws CacheException {
        map.put(key, value);
    }

    public void remove(Object key) throws CacheException {
        map.remove(key);
    }

    public void clear() throws CacheException {
        map.clear();
    }

    public int size() {
        return map.size();
    }

    @SuppressWarnings({"unchecked"})
    public Set keys() {
        Set keys = map.keySet();
        if (!keys.isEmpty()) {
            return Collections.unmodifiableSet(keys);
        }
        return Collections.EMPTY_SET;
    }

    @SuppressWarnings({"unchecked"})
    public Set values() {
        if (!map.isEmpty()) {
            Collection values = map.values();
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
        return new StringBuilder("MapCache '")
                .append(name).append("' (")
                .append(map.size())
                .append(" entries)")
                .toString();
    }
}
