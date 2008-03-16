/*
* Copyright (C) 2005-2008 Jeremy Haile, Les Hazlewood
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
package org.jsecurity.cache;

import java.util.Set;

/**
 * A Cache efficiently stores temporary objects primarily to improve an application's performance.
 *
 * <p>JSecurity doesn't implement a full Cache mechanism itself, since that is outside the core competency of a 
 * Security framework.  Instead, this interface provides an abstraction (wrapper) API on top of an underlying
 * cache framework's cache instance (e.g. JCache, Ehcache, JCS, OSCache, JBossCache, TerraCotta, Coherence,
 * GigaSpaces, etc, etc), allowing a JSecurity user to configure any cache mechanism they choose.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public interface Cache {

    /**
     * Returns the Cached value stored under the specified <code>key</code> or
     * <code>null</code> if there is no Cache entry for that <code>key</code>.
     *
     * @param key the key that the value was previous added with
     * @return the cached object or <tt>null</tt> if there is no Cache entry for the specified <code>key</code>
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public Object get( Object key ) throws CacheException;

    /**
     * Adds a Cache entry.
     *
     * @param key   the key used to identify the object being stored.
     * @param value the value to be stored in the cache.
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public void put( Object key, Object value ) throws CacheException;

    /**
     * Remove the cache entry corresponding to the specified key.
     *
     * @param key the key of the entry to be removed.
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public void remove( Object key ) throws CacheException;

    /**
     * Clear all entries from the cache.
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public void clear() throws CacheException;

    /**
     * Returns the number of entries in the cache.
     * @return the number of entries in the cache.
     */
    public int size();

    /**
     * Returns a view of all the keys for entries contained in this cache.
     * @return a view of all the keys for entries contained in this cache.
     */
    public Set keys();

    /**
     * Returns a view of all of the values contained in this cache.
     * @return a view of all of the values contained in this cache.
     */
    public Set values();
}