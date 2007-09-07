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

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JSecurity {@link org.jsecurity.cache.Cache} implementation that wraps an EhCache cache.
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
     * The underlying EhCache cache used by this JSecurity cache.
     */
    private net.sf.ehcache.Cache cache;

    /**
     * Constructs a new EhCache instance with the given cache.
     * @param cache - delegate EhCache instance this JSecurity cache instance will wrap.
     */
    public EhCache(net.sf.ehcache.Cache cache) {
        this.cache = cache;
    }

    public String getCacheName() {
        return cache.getName();
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
                logger.trace("Getting object from cache [" + getCacheName() + "] for key [" + key + "]");
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
     * @param key   the key associated with the object
     * @param value the value associated with the key.
     */
    public void update(Object key, Object value) throws CacheException {
        put(key, value);
    }

    /**
     * Puts an object into the cache.
     *
     * @param key   the key.
     * @param value the value.
     */
    public void put(Object key, Object value) throws CacheException {

        if (logger.isTraceEnabled()) {
            logger.trace("Putting object in cache [" + getCacheName() + "] for key [" + key + "]");
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
            logger.trace("Removing object from cache [" + getCacheName() + "] for key [" + key + "]");
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
            logger.trace("Clearing all objects from cache [" + getCacheName() + "]");
        }
        try {
            cache.removeAll();
        } catch ( Throwable t ) {
            throw new CacheException( t );
        }
    }

    /**
     * Remove the cache and make it unuseable.
     */
    public void destroy() throws CacheException {
        if ( logger.isDebugEnabled() ) {
            logger.debug( "Cleaning up and removing cache [" + getCacheName() + "]" );
        }
        try {
            //TODO - may not be the VM cacheManager that created this cache.
            CacheManager.getInstance().removeCache(cache.getName());
        }
        catch ( Throwable t ) {
            throw new CacheException(t);
        }
    }


    public long getSizeInMemory() {
        try {
            return cache.calculateInMemorySize();
        }
        catch (Throwable t) {
            return -1;
        }
    }


    public long getElementCount() {
        try {
            return cache.getSize();
        } catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public long getElementCountInMemory() {
        try {
            return cache.getMemoryStoreSize();
        }
        catch (Throwable t) {
            throw new CacheException(t);
        }
    }

    public long getElementCountOnDisk() {
        try {
            return cache.getDiskStoreSize();
        } catch ( Throwable t ) {
            throw new CacheException(t);
        }
    }

    public Map toMap() {
        try {
            Map result = new HashMap();
            if (cache != null) {
                List keys = cache.getKeys();
                for (Object key : keys) {
                    Element cacheElement = cache.get(key);
                    if (cacheElement != null) {
                        Object value = cacheElement.getValue();
                        if (value != null) {
                            result.put(key, value);
                        }
                    }
                }
            }
            return Collections.unmodifiableMap(result);
        }
        catch ( Throwable t ) {
            throw new CacheException(t);
        }
    }

    public String toString() {
        return "EhCache [" + getCacheName() + "]";
    }
}