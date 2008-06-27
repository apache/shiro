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
import org.jsecurity.realm.text.PropertiesRealm;
import org.jsecurity.util.LifecycleUtils;

import java.util.ArrayList;
import java.util.Collection;

/**
 * JSecurity support of a {@link SecurityManager} class hierarchy based around a collection of
 * {@link org.jsecurity.realm.Realm}s.  All actual <tt>SecurityManager</tt> method implementations are left to
 * subclasses.
 *
 * <p>Upon {@link #init() initialization}, a default <tt>Realm</tt> will be created automatically if one has not
 * been provided, but please note:
 *
 * <p>Unless you're happy with the default simple {@link org.jsecurity.realm.text.PropertiesRealm properties file}-based realm, which may or
 * may not be flexible enough for enterprise applications, you might want to specify at least one custom
 * <tt>Realm</tt> implementation that 'knows' about your application's data/security model
 * (via {@link #setRealm} or one of the overloaded constructors).  All other attributes in this class hierarchy
 * will have suitable defaults for most enterprise applications.</p>
 *
 * <p>The only absolute requirement for a <tt>RealmSecurityManager</tt> instance to function properly is
 * that its {@link #init() init()} method must be called before it is used.  Even this is called automatically if
 * you use one of the overloaded constructors with one or more arguments.</p>
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class RealmSecurityManager extends CachingSecurityManager {

    protected Collection<Realm> realms;

    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public RealmSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application (automatically calls {@link #init()} before returning).
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public RealmSecurityManager(Realm singleRealm) {
        setRealm(singleRealm);
        init();
    }

    /**
     * Supporting constructor that sets the {@link #setRealms realms} property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public RealmSecurityManager(Collection<Realm> realms) {
        setRealms(realms);
        init();
    }


    /**
     * Convenience method for applications with a single realm that merely wraps the realm in a list and then invokes
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

    public Collection<Realm> getRealms() {
        return realms;
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
    }

    protected void afterCacheManagerSet() {
        ensureRealms();
        applyRealmsCacheManager();
        afterRealmsSet();
    }

    protected void ensureRealms() {
        Collection<Realm> realms = getRealms();
        if (realms == null || realms.isEmpty()) {
            if (log.isInfoEnabled()) {
                log.info("No realms set - creating default Realm instance.");
            }
            Realm realm = createDefaultRealm();
            setRealm(realm);
        }
    }

    protected void applyRealmsCacheManager() {
        Collection<Realm> realms = getRealms();
        CacheManager cacheManager = getCacheManager();
        if (cacheManager != null && realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof CacheManagerAware) {
                    ((CacheManagerAware) realm).setCacheManager(cacheManager);
                }
            }
        }
    }

    protected Realm createDefaultRealm() {
        PropertiesRealm propsRealm = new PropertiesRealm();
        if (getCacheManager() != null) {
            propsRealm.setCacheManager(getCacheManager());
        }
        propsRealm.init();
        return propsRealm;
    }

    protected void afterRealmsSet() {
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
