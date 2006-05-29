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
package org.jsecurity.cache;

import org.jsecurity.Configuration;

/**
 * Interface for cache-specific implementations that can provide caches
 * used by JSecurity to cache authentication and/or authorization information.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public interface CacheProvider {


        /**
         * Callback to perform any necessary initialization of the underlying cache implementation
         * during application initialization.
         *
         * @param configuration current configuration settings.
         */
        public void init(Configuration configuration) throws CacheException;

        /**
         * Callback to perform any necessary cleanup of the underlying cache implementation during
         * application destruction.
         */
        public void destroy();

        /**
         * Configure and creates a cache with the given name using the specified
         * properties for configuration.
         *
         * @param cacheName the name of the cache to create.
         * @param configuration settings used when creating this cache.
         */
        public Cache buildCache(String cacheName, Configuration configuration) throws CacheException;


}