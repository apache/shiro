/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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
package org.jsecurity.realm.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
import org.jsecurity.realm.Realm;

/**
 * <p>A very basic abstract implementation of the {@link Realm} interface that provides
 * logging support, caching support, and a simple {@link #getName() name} default.  Most all logic is left to subclasses.
 *
 * @since 0.2
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public abstract class AbstractRealm implements Realm, CacheProviderAware {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * Commons-logger.
     */
    protected transient final Log log = LogFactory.getLog( getClass() );


    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private static int INSTANCE_COUNT = 0;

    /**
     * The name of this realm.
     */
    private String name = getClass().getName() + "-" + INSTANCE_COUNT++;
    
    private CacheProvider cacheProvider = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AbstractRealm(){}

    public AbstractRealm( String name ) {
        setName( name );
    }

    protected AbstractRealm( String name, CacheProvider cacheProvider ) {
        this( name );
        setCacheProvider( cacheProvider );
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Returns the name assigned to this realm instance.  Names must be unique across all realms configured in the
     * system.
     *
     * @return the name associated with this realm instance.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Sets the name associated with the realm instance.  Names must be unique across all realms configured in the
     * system.
     *
     * <p>Unless overridden, a default name based on the class name and a static increment attribute is used.
     *
     * @param name the unique name assigned to the realm instance.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets the <tt>CacheProvider</tt> to be used for data caching to reduce EIS round trips.
     *
     * <p>This property is <tt>null</tt> by default, indicating that caching is turned off.
     *
     * @param authzInfoCacheProvider the <tt>CacheProvider</tt> to use for data caching, or <tt>null</tt> to disable caching.
     */
    public void setCacheProvider( CacheProvider authzInfoCacheProvider) {
        this.cacheProvider = authzInfoCacheProvider;
    }

    /**
     * Returns the <tt>CacheProvider</tt> used for data caching to reduce EIS round trips, or <tt>null</tt> if
     * caching is disabled.
     *
     * @return the <tt>CacheProvider</tt> used for data caching to reduce EIS round trips, or <tt>null</tt> if
     * caching is disabled.
     */
    public CacheProvider getCacheProvider() {
        return this.cacheProvider;
    }
}