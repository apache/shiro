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
package org.jsecurity.cache;

import java.util.Map;

/**
 * Interface encapsulating logic related to a single cache used for caching
 * JSecurity authentication and authorization information.
 * 
 * @since 0.2
 * @author Jeremy Haile
 */
public interface Cache {

    /**
     * The name associated with this cache.  This should usually be
     * unique for all caches associated with a particular
     * {@link CacheProvider}
     *
     * @return the unique name of this cache.
     */
    public String getCacheName();

    /**
     * Get an item from the cache.
     *
     * @param key the key that the item was previous stored with.
     * @return the cached object or <tt>null</tt>
     */
    public Object get( Object key ) throws CacheException;

    /**
     * Add an item to the cache.
     *
     * @param key   the key used to identify the object being stored.
     * @param value the value to be stored in the cache.
     */
    public void put( Object key, Object value ) throws CacheException;

    /**
     * Update an existing item in the cache.
     *
     * @param key   the key of the item being updated.
     * @param value the new value of the item being updated.
     */
    public void update( Object key, Object value ) throws CacheException;

    /**
     * Remove an item from the cache.
     *
     * @param key the key of the item to be removed.
     */
    public void remove( Object key ) throws CacheException;

    /**
     * Clear all objects from the cache.
     */
    public void clear() throws CacheException;

    /**
     * Clean up any resources used by this cache.
     */
    public void destroy() throws CacheException;

    /**
     * The number of bytes that this cache is currently using in memory.
     *
     * @return The number of bytes consumed by this cache, or -1 if unknown or
     *         unsupported.
     */
    public long getSizeInMemory();

    /**
     * Returns the number of cache entries currently contained in the cache (sum of both in-memory and on disk).
     *
     * @return the number of cache entries currently contained in the cache (sum both in-memory and on disk).
     */
    public long getElementCount();

    /**
     * The number of cache entries currently contained in the cache's in-memory store.
     *
     * @return The count of entries in memory, or -1 if unknown or unsupported.
     */
    public long getElementCountInMemory();

    /**
     * The count of entries currently contained in the cache's disk store.
     *
     * @return The count of entries on disk, or -1 if unknown or unsupported.
     */
    public long getElementCountOnDisk();


    /**
     * Converts the contents of this cache to a map for debugging or
     * reporting purposes.
     *
     * @return the contents of this cache as a map.
     */
    public Map toMap();
}