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

import java.util.Hashtable;

/**
 * An implementation of the Ki {@link Cache} interface that uses a
 * {@link Hashtable} to store cached objects.  This implementation is only suitable for
 * development/testing use as it is prone to a potential memory leak if objects are not explicitly removed
 * from the cache.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.2
 *
 * @deprecated Due to potential memory leaks caused by {@code Hashtable}s, it is highly recommended to avoid using
 * this class and instead switch to using a {@link SoftHashMapCache SoftHashMapCache}.
 */
public class HashtableCache extends MapCache {

    /**
     * Creates a new <code>HashtableCache</code> instance with the specified name.
     * <p/>
     * This constructor simply calls <code>super(name, new {@link Hashtable Hashtable}());</code>
     *
     * @param name the name to assign to the cache.
     * @since 1.0
     */
    public HashtableCache(String name) {
        super(name, new Hashtable());
    }

}
