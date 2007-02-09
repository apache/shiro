/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.session.support.eis.ehcache;

import net.sf.ehcache.CacheManager;
import org.jsecurity.cache.ehcache.EhCacheProvider;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.session.support.eis.support.MemorySessionDAO;

/**
 * Provides memory caching <em>and</em> disk-based caching for production environments via Ehcache.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class EhcacheSessionDAO extends MemorySessionDAO {

    private CacheManager manager;
    private String configurationResourceName = "EhcacheSessionDAO.defaultSettings.ehcache.xml";

    public EhcacheSessionDAO() {
        setCacheProvider( new EhCacheProvider() );
        setMaintainStoppedSessions( false );
    }

    public void setCacheManager( CacheManager cacheManager ) {
        this.manager = cacheManager;
    }

    public void setConfigurationResourceName( String configurationResourceName ) {
        this.configurationResourceName = configurationResourceName;
    }

    public void init() {
        CacheProvider provider = this.cacheProvider;
        if ( provider == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "no EhCacheProvider specified.  Creating one automatically..." );
            }
            EhCacheProvider ehCacheProvider = new EhCacheProvider();

            if ( manager != null ) {
                ehCacheProvider.setCacheManager( manager );
            }
            if ( configurationResourceName != null ) {
                ehCacheProvider.setConfigurationResourceName( configurationResourceName );
            }
            ehCacheProvider.init();

            setCacheProvider( ehCacheProvider );
        }

        super.init();
    }
}
