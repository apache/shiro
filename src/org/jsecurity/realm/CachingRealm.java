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
package org.jsecurity.realm;

import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>A very basic abstract extension point for the {@link Realm} interface that provides logging and caching support.
 *
 * <p>All actual Realm method implementations are left to subclasses.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class CachingRealm implements Realm, CacheManagerAware {

    private static int INSTANCE_COUNT = 0;

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    protected transient final Logger log = LoggerFactory.getLogger(getClass());

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private String name = getClass().getName() + "_" + INSTANCE_COUNT++;

    private CacheManager cacheManager;

    public CachingRealm() {
    }

    public CachingRealm(CacheManager cacheManager) {
        setCacheManager(cacheManager);
    }

    /**
     * Sets the <tt>CacheManager</tt> to be used for data caching to reduce EIS round trips.
     *
     * <p>This property is <tt>null</tt> by default, indicating that caching is turned off.
     *
     * @param authzInfoCacheManager the <tt>CacheManager</tt> to use for data caching, or <tt>null</tt> to disable caching.
     */
    public void setCacheManager(CacheManager authzInfoCacheManager) {
        this.cacheManager = authzInfoCacheManager;
    }

    /**
     * Returns the <tt>CacheManager</tt> used for data caching to reduce EIS round trips, or <tt>null</tt> if
     * caching is disabled.
     *
     * @return the <tt>CacheManager</tt> used for data caching to reduce EIS round trips, or <tt>null</tt> if
     *         caching is disabled.
     */
    public CacheManager getCacheManager() {
        return this.cacheManager;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
