/*
* Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.ri.cache.support;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * JSecurity {@link Cache} implementation that wraps an EhCache cache.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
@SuppressWarnings( "unchecked" )
public class EhCache implements Cache {

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The underlying EhCache cache used by this JSecurity cache.
     */
    private net.sf.ehcache.Cache cache;

    /**
     * Constructs a new EhCache instance with the given cache.
     */
    public EhCache(net.sf.ehcache.Cache cache) {
        this.cache = cache;
    }

    public String getCacheName() {
        return cache.getName();
    }

    /**
     * Gets a value of an element which matches the given key.
     * @param key the key of the element to return.
     * @return The value placed into the cache with an earlier put, or null if not found or expired
     */
    public Object get(Object key) throws CacheException {
        try {
            if ( logger.isDebugEnabled() ) {
                logger.debug("Getting object from cache [" + getCacheName() + "] for key [" + key + "]");
            }
            if (key == null) {
                return null;
            }
            else {
                Element element = cache.get( key );
                if (element == null) {
                    if ( logger.isDebugEnabled() ) {
                        logger.debug("Element for [" + key + "] is null.");
                    }
                    return null;
                }
                else {
                    return element.getObjectValue();
                }
            }
        }
        catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }


    /**
     * Puts an object into the cache.
     * @param key the key associated with the object
     * @param value the value associated with the key.
     */
    public void update(Object key, Object value) throws CacheException {
        put(key, value);
    }

    /**
     * Puts an object into the cache.
     * @param key the key.
     * @param value the value.
     */
    public void put(Object key, Object value) throws CacheException {

        if (logger.isDebugEnabled()) {
            logger.debug("Putting object in cache [" + getCacheName() + "] for key [" + key + "]" );
        }

        try {
            Element element = new Element( key, value );
            cache.put(element);
        }
        catch (IllegalArgumentException e) {
            throw new CacheException(e);
        }
        catch (IllegalStateException e) {
            throw new CacheException(e);
        }

    }

    /**
     * Removes the element which matches the key.
     * <p>
     * If no element matches, nothing is removed and no Exception is thrown.
     * @param key the key of the element to remove
     */
    public void remove(Object key) throws CacheException {

        if (logger.isDebugEnabled()) {
            logger.debug("Removing object from cache [" + getCacheName() + "] for key [" + key + "]" );
        }
        try {
            cache.remove( key );
        }
        catch (ClassCastException e) {
            throw new CacheException(e);
        }
        catch (IllegalStateException e) {
            throw new CacheException(e);
        }
    }

    /**
     * Remove all elements in the cache, but leave the cache
     * in a useable state.
     */
    public void clear() throws CacheException {

        if (logger.isDebugEnabled()) {
            logger.debug("Clearing all objects from cache [" + getCacheName() + "]" );
        }
        try {
            cache.removeAll();
        }
        catch (IllegalStateException e) {
            throw new CacheException(e);
        }
        catch (IOException e) {
            throw new CacheException(e);
        }
    }

    /**
     * Remove the cache and make it unuseable.
     */
    public void destroy() throws CacheException {
        try {
            CacheManager.getInstance().removeCache( cache.getName() );
        }
        catch (IllegalStateException e) {
            throw new CacheException(e);
        }
        catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }


    public long getSizeInMemory() {
        try {
            return cache.calculateInMemorySize();
        }
        catch(Throwable t) {
            return -1;
        }
    }

    public long getElementCountInMemory() {
        try {
            return cache.getSize();
        }
        catch (net.sf.ehcache.CacheException ce) {
            throw new CacheException(ce);
        }
    }

    public long getElementCountOnDisk() {
        return cache.getDiskStoreSize();
    }

    public Map toMap() {
        try {
            Map result = new HashMap();
            for (Object key : cache.getKeys()) {
                Object value = cache.get(key).getValue();
                result.put(key, value);
            }
            return Collections.unmodifiableMap( result );
        }
        catch (Exception e) {
            throw new CacheException(e);
        }
    }

    public String toString() {
        return "EhCache [" + getCacheName() + "]";
    }
}