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
package org.apache.ki.cache;

import org.apache.ki.util.SoftHashMap;

/**
 * A MapCache that uses a {@link SoftHashMap SoftHashMap} as its backing map.
 * <p/>
 * This implementation is suitable in production environments, but does not offer any enterprise features like
 * cache coherency, replication, optimistic locking, or other features.  It is only a memory-constrained map.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SoftHashMapCache extends MapCache {

    /**
     * Creates a new <code>SoftHashMapCache</code> instance with the specified name.
     * <p/>
     * This constructor simply calls <code>super(name, new {@link SoftHashMap SoftHashMap}());</code>
     *
     * @param name the name to assign to the cache.
     */
    public SoftHashMapCache(String name) {
        super(name, new SoftHashMap());
    }
}
