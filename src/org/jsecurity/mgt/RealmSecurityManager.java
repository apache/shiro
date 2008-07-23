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
package org.jsecurity.mgt;

import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.LifecycleUtils;

import java.util.ArrayList;
import java.util.Collection;

/**
 * JSecurity support of a {@link SecurityManager} class hierarchy based around a collection of
 * {@link org.jsecurity.realm.Realm}s.  All actual <tt>SecurityManager</tt> method implementations are left to
 * subclasses.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class RealmSecurityManager extends CachingSecurityManager {

    protected Collection<Realm> realms;

    /**
     * Default no-arg constructor.
     */
    public RealmSecurityManager() {
    }

    /**
     * Convenience method for applications using a single realm that merely wraps the realm in a list and then invokes
     * the {@link #setRealms} method.
     *
     * @param realm the realm to set for a single-realm application.
     * @since 0.2
     */
    public void setRealm(Realm realm) {
        if (realm == null) {
            throw new IllegalArgumentException("Realm argument cannot be null");
        }
        Collection<Realm> realms = new ArrayList<Realm>(1);
        realms.add(realm);
        setRealms(realms);
    }

    /**
     * Sets the realms managed by this <tt>SecurityManager</tt> instance.
     *
     * @param realms the realms managed by this <tt>SecurityManager</tt> instance.
     */
    public void setRealms(Collection<Realm> realms) {
        if (realms == null) {
            throw new IllegalArgumentException("Realms collection argument cannot be null.");
        }
        if (realms.isEmpty()) {
            throw new IllegalArgumentException("Realms collection argument cannot be empty.");
        }
        this.realms = realms;
        applyCacheManagerToRealms();
    }

    /**
     * Returns the {@link Realm Realm}s managed by this SecurityManager instance.
     *
     * @return the {@link Realm Realm}s managed by this SecurityManager instance.
     */
    public Collection<Realm> getRealms() {
        return realms;
    }

    protected void applyCacheManagerToRealms() {
        CacheManager cacheManager = getCacheManager();
        Collection<Realm> realms = getRealms();
        if (cacheManager != null) {
            for (Realm realm : realms) {
                if (realm instanceof CacheManagerAware) {
                    ((CacheManagerAware) realm).setCacheManager(cacheManager);
                }
            }
        }
    }

    protected void afterCacheManagerSet() {
        applyCacheManagerToRealms();
    }

    protected void beforeCacheManagerDestroyed() {
        beforeRealmsDestroyed();
        destroyRealms();
    }

    protected void beforeRealmsDestroyed() {
    }

    protected void destroyRealms() {
        Collection<Realm> realms = getRealms();
        if (realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                LifecycleUtils.destroy(realm);
            }
        }
        this.realms = null;
    }

}
