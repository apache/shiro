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
package org.apache.shiro.mgt;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.CacheManagerAware;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.lang.util.LifecycleUtils;

import java.util.ArrayList;
import java.util.Collection;


/**
 * Shiro support of a {@link SecurityManager} class hierarchy based around a collection of
 * {@link org.apache.shiro.realm.Realm}s.  All actual {@code SecurityManager} method implementations are left to
 * subclasses.
 *
 * @since 0.9
 */
public abstract class RealmSecurityManager extends CachingSecurityManager {

    /**
     * Internal collection of <code>Realm</code>s used for all authentication and authorization operations.
     */
    private Collection<Realm> realms;

    /**
     * Default no-arg constructor.
     */
    public RealmSecurityManager() {
        super();
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
     * @throws IllegalArgumentException if the realms collection is null or empty.
     */
    public void setRealms(Collection<Realm> realms) {
        if (realms == null) {
            throw new IllegalArgumentException("Realms collection argument cannot be null.");
        }
        if (realms.isEmpty()) {
            throw new IllegalArgumentException("Realms collection argument cannot be empty.");
        }
        this.realms = realms;
        afterRealmsSet();
    }

    protected void afterRealmsSet() {
        applyCacheManagerToRealms();
        applyEventBusToRealms();
    }

    /**
     * Returns the {@link Realm Realm}s managed by this SecurityManager instance.
     *
     * @return the {@link Realm Realm}s managed by this SecurityManager instance.
     */
    public Collection<Realm> getRealms() {
        return realms;
    }

    /**
     * Sets the internal {@link #getCacheManager CacheManager} on any internal configured
     * {@link #getRealms Realms} that implement the {@link org.apache.shiro.cache.CacheManagerAware CacheManagerAware} interface.
     * <p/>
     * This method is called after setting a cacheManager on this securityManager via the
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) setCacheManager} method to allow it to be propagated
     * down to all the internal Realms that would need to use it.
     * <p/>
     * It is also called after setting one or more realms via the {@link #setRealm setRealm} or
     * {@link #setRealms setRealms} methods to allow these newly available realms to be given the cache manager
     * already in use.
     */
    protected void applyCacheManagerToRealms() {
        CacheManager cacheManager = getCacheManager();
        Collection<Realm> realms = getRealms();
        if (cacheManager != null && realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof CacheManagerAware) {
                    ((CacheManagerAware) realm).setCacheManager(cacheManager);
                }
            }
        }
    }

    /**
     * Sets the internal {@link #getEventBus  EventBus} on any internal configured
     * {@link #getRealms Realms} that implement the {@link EventBusAware} interface.
     * <p/>
     * This method is called after setting an eventBus on this securityManager via the
     * {@link #setEventBus(org.apache.shiro.event.EventBus) setEventBus} method to allow it to be propagated
     * down to all the internal Realms that would need to use it.
     * <p/>
     * It is also called after setting one or more realms via the {@link #setRealm setRealm} or
     * {@link #setRealms setRealms} methods to allow these newly available realms to be given the EventBus
     * already in use.
     *
     * @since 1.3
     */
    protected void applyEventBusToRealms() {
        EventBus eventBus = getEventBus();
        Collection<Realm> realms = getRealms();
        if (eventBus != null && realms != null && !realms.isEmpty()) {
            for(Realm realm : realms) {
                if (realm instanceof EventBusAware) {
                    ((EventBusAware)realm).setEventBus(eventBus);
                }
            }
        }
    }

    /**
     * Simply calls {@link #applyCacheManagerToRealms() applyCacheManagerToRealms()} to allow the
     * newly set {@link org.apache.shiro.cache.CacheManager CacheManager} to be propagated to the internal collection of <code>Realm</code>
     * that would need to use it.
     */
    protected void afterCacheManagerSet() {
        super.afterCacheManagerSet();
        applyCacheManagerToRealms();
    }

    @Override
    protected void afterEventBusSet() {
        super.afterEventBusSet();
        applyEventBusToRealms();
    }

    public void destroy() {
        LifecycleUtils.destroy(getRealms());
        this.realms = null;
        super.destroy();
    }

}
