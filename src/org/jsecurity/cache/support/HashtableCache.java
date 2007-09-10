/*
* Copyright (C) 2005-2007 Jeremy Haile
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

package org.jsecurity.cache.support;

import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;

import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;

/**
 * An implementation of the JSecurity {@link Cache} interface that uses a
 * {@link Hashtable} to store cached objects.  This implementation is only suitable for
 * development/testing use.  A more robust caching solution should be used for production
 * systems such as the {@link org.jsecurity.cache.ehcache.EhCacheProvider}
 *
 * @since 0.2
 * @author Jeremy Haile
 */
@SuppressWarnings( "unchecked" )
public class HashtableCache implements Cache {

    /**
     * The underlying hashtable.
     */
    private final Map hashtable = new Hashtable();

    /**
     * The name of this cache.
     */
    private final String cacheName;


    /**
     * Creates a new cache with the given name.
     *
     * @param cacheName the name of this cache.
     */
    public HashtableCache( String cacheName ) {
        this.cacheName = cacheName;
    }

    public String getCacheName() {
        return cacheName;
    }

    public Object read( Object key ) throws CacheException {
        return hashtable.get( key );
    }

    public Object get( Object key ) throws CacheException {
        return hashtable.get( key );
    }

    public void update( Object key, Object value ) throws CacheException {
        put( key, value );
    }

    public void put( Object key, Object value ) throws CacheException {
        hashtable.put( key, value );
    }

    public void remove( Object key ) throws CacheException {
        hashtable.remove( key );
    }

    public void clear() throws CacheException {
        hashtable.clear();
    }

    public void destroy() throws CacheException {
        clear();
    }

    public long getSizeInMemory() {
        return -1;
    }


    public long getElementCount() {
        return hashtable.size();
    }

    public long getElementCountInMemory() {
        return getElementCount();
    }

    public long getElementCountOnDisk() {
        return 0;
    }

    public Map toMap() {
        return Collections.unmodifiableMap( hashtable );
    }

    public String toString() {
        return "HashtableCache [" + cacheName + "]";
    }
}