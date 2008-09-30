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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.text.PropertiesRealm;
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

    /**
     * Internal private log instance.
     */
    private static final Log log = LogFactory.getLog(RealmSecurityManager.class);

    /**
     * Internal collection of <code>Realm</code>s used for all authentication and authorization operations.
     */
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
     * Ensures at least one realm exists, and if not calls {@link #createDefaultRealm() createDefaultRealm()} and sets
     * it on this instance via the {@link #setRealm(Realm) setRealm} method.
     * <p/>
     * This method is used to lazily ensure at least one default Realm exists in all environments, even if it is just
     * with demo data, to ensure that JSecurity is usuable with the smallest (even no) configuration.
     */
    protected void ensureRealms() {
        Collection<Realm> realms = getRealms();
        if (realms == null || realms.isEmpty()) {
            if (log.isInfoEnabled()) {
                log.info("No Realms configured.  Defaulting to failsafe PropertiesRealm.");
            }
            Realm realm = createDefaultRealm();
            setRealm(realm);
        }
    }

    /**
     * Creates a default Realm implementation to use in lazy-initialization use cases.
     * <p/>
     * The implementation returned is a {@link PropertiesRealm PropertiesRealm}, which supports very simple
     * properties-based user/role/permission configuration in testing, sample, and simple applications.
     * @return the default Realm implementation (a {@link PropertiesRealm PropertiesRealm} to use in lazy-init use cases.
     */
    protected Realm createDefaultRealm() {
        PropertiesRealm realm;
        CacheManager cacheManager = getCacheManager();
        if (cacheManager != null) {
            realm = new PropertiesRealm(cacheManager);
        } else {
            realm = new PropertiesRealm();
        }
        return realm;
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
     * {@link #getRealms Realms} that implement the {@link CacheManagerAware CacheManagerAware} interface.
     * <p/>
     * This method is called after setting a cacheManager on this securityManager via the
     * {@link #setCacheManager(org.jsecurity.cache.CacheManager) setCacheManager} method to allow it to be propagated
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
     * Simply calls {@link #applyCacheManagerToRealms() applyCacheManagerToRealms()} to allow the
     * newly set {@link CacheManager CacheManager} to be propagated to the internal collection of <code>Realm</code>
     * that would need to use it.
     *
     */
    protected void afterCacheManagerSet() {
        applyCacheManagerToRealms();
    }

    /**
     * First calls {@link #beforeRealmsDestroyed() beforeRealmsDestroyed()} to allow subclasses to clean up
     * first, then calls {@link #destroyRealms() destroyRealms()} to clean up the internal <code>Realm</code>s
     * collection.
     */
    protected void beforeCacheManagerDestroyed() {
        beforeRealmsDestroyed();
        destroyRealms();
    }

    /**
     * Template hook for subclasses to perform clean up logic during shut-down.
     */
    protected void beforeRealmsDestroyed() {
    }

    /**
     * Cleans up ('destroys') the internal collection of Realms by calling
     * {@link LifecycleUtils#destroy(Collection) LifecycleUtils.destroy(getRealms())}.
     */
    protected void destroyRealms() {
        LifecycleUtils.destroy(getRealms());
        this.realms = null;
    }

}
