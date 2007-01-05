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

package org.jsecurity.cache.support;

import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheProvider;

/**
 * A {@link CacheProvider} that returns {@link HashtableCache} caches.
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class HashtableCacheProvider implements CacheProvider {

    /**
     * Builds a new {@link HashtableCache} with the given name.
     * @param cacheName the name of the new cache to create.
     * @return a new cache.
     */
    public Cache buildCache( String cacheName ) {
        return new HashtableCache( cacheName );
    }
}