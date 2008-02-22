/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity;

import org.jsecurity.realm.PropertiesRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.LifecycleUtils;

import java.util.ArrayList;
import java.util.Collection;

/**
 * JSecurity support of a {@link org.jsecurity.SecurityManager} class hierarchy based around a collection of
 * {@link org.jsecurity.realm.Realm}s.  All actual <tt>SecurityManager</tt> method implementations are left to
 * subclasses.
 *
 * <p>Upon {@link #init() initialization}, a default <tt>Realm</tt> will be created automatically if one has not
 * been provided, but please note:
 *
 * <p>Unless you're happy with the default simple {@link org.jsecurity.realm.PropertiesRealm properties file}-based realm, which may or
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

    protected Collection<Realm> realms = null;

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

    protected Realm createDefaultRealm() {
        PropertiesRealm propsRealm = new PropertiesRealm();
        propsRealm.setCacheProvider(getCacheProvider());
        propsRealm.init();
        return propsRealm;
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

    protected void afterCacheProviderSet() {
        ensureRealms();
        afterRealmsSet();
    }

    protected void afterRealmsSet(){}

    protected void beforeRealmsDestroyed(){}

    protected void destroyRealms() {
        Collection<Realm> realms = getRealms();
        if (realms != null && !realms.isEmpty()) {
            for ( Realm realm : realms ) {
                LifecycleUtils.destroy( realm );
            }
        }
        this.realms = null;
    }

    protected void beforeCacheProviderDestroyed() {
        beforeRealmsDestroyed();
        destroyRealms();
    }
}
