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
package org.jsecurity.cache.ehcache;

import net.sf.ehcache.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * JSecurity {@link org.jsecurity.cache.Cache} implementation that wraps an {@link net.sf.ehcache.Ehcache}.
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
@SuppressWarnings("unchecked")
public class EhCache implements Cache {

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The wrapped Ehcache instance.
     */
    private net.sf.ehcache.Ehcache cache;

    /**
     * Constructs a new EhCache instance with the given cache.
     * @param cache - delegate EhCache instance this JSecurity cache instance will wrap.
     */
    public EhCache(net.sf.ehcache.Cache cache ) {
        if ( cache == null ) {
            throw new IllegalArgumentException( "Cache argument cannot be null." );
        }
        this.cache = cache;
    }

    /**
     * Gets a value of an element which matches the given key.
     *
     * @param key the key of the element to return.
     * @return The value placed into the cache with an earlier put, or null if not found or expired
     */
    public Object get(Object key) throws CacheException {
        try {
            if (logger.isTraceEnabled()) {
                logger.trace("Getting object from cache [" + cache.getName() + "] for key [" + key + "]");
            }
            if (key == null) {
                return null;
            } else {
                Element element = cache.get(key);
                if (element == null) {
                    if (logger.isTraceEnabled()) {
                        logger.trace("Element for [" + key + "] is null.");
                    }
                    return null;
                } else {
                    return element.getObjectValue();
                }
            }
        }
        catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Puts an object into the cache.
     *
     * @param key   the key.
     * @param value the value.
     */
    public void put(Object key, Object value) throws CacheException {

        if (logger.isTraceEnabled()) {
            logger.trace("Putting object in cache [" + cache.getName() + "] for key [" + key + "]");
        }

        try {
            Element element = new Element(key, value);
            cache.put(element);
        }
        catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Removes the element which matches the key.
     * <p/>
     * If no element matches, nothing is removed and no Exception is thrown.
     *
     * @param key the key of the element to remove
     */
    public void remove(Object key) throws CacheException {

        if (logger.isTraceEnabled()) {
            logger.trace("Removing object from cache [" + cache.getName() + "] for key [" + key + "]");
        }
        try {
            cache.remove(key);
        }
        catch ( Throwable t) {
            throw new CacheException(t);
        }
    }

    /**
     * Remove all elements in the cache, but leave the cache
     * in a useable state.
     */
    public void clear() throws CacheException {

        if (logger.isTraceEnabled()) {
            logger.trace("Clearing all objects from cache [" + cache.getName() + "]");
        }
        try {
            cache.removeAll();
        } catch ( Throwable t ) {
            throw new CacheException( t );
        }
    }

    public int size() {
        try {
            return cache.getSize();
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public Set keys() {
        try {
            List keys = cache.getKeys();
            if ( keys != null && !keys.isEmpty() ) {
                return Collections.unmodifiableSet( new LinkedHashSet( keys ) );
            } else {
                return Collections.EMPTY_SET;
            }
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public Set values() {
        try {
            List keys = cache.getKeys();
            if ( keys != null && !keys.isEmpty() ) {
                Set values = new LinkedHashSet(keys.size());
                for( Object key : keys ) {
                    values.add( cache.get(key) );
                }
                return Collections.unmodifiableSet( values );
            } else {
                return Collections.EMPTY_SET;
            }
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public long getMemoryUsage() {
        try {
            return cache.calculateInMemorySize();
        }
        catch (Throwable t) {
            return -1;
        }
    }

    public long getMemoryStoreSize() {
        try {
            return cache.getMemoryStoreSize();
        }
        catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public long getDiskStoreSize() {
        try {
            return cache.getDiskStoreSize();
        } catch ( Throwable t ) {
            throw new CacheException(t);
        }
    }

    public String toString() {
        return "EhCache [" + cache.getName() + "]";
    }
}