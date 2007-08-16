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
import org.jsecurity.session.support.eis.support.MemorySessionDAO;
import org.jsecurity.util.Destroyable;

/**
 * Provides memory caching <em>and</em> disk-based caching for production environments via Ehcache.
 *
 * <p>This implementation is intended to be used on its own and not necessarily when a relational database will be used
 * to store sessions.
 *
 * <p>However, if a RDBMS will be used to store sessions and you wish to use this class as a parent, you must override
 * all of the parent {@link MemorySessionDAO MemorySessionDAO} methods (doCreate, doReadSession, etc) to interact w/
 * the underlying RDBMS (e.g. via JDBC or Hibernate or JPA, etc).
 *
 * <p>Note that if using Hibernate or JPA for example, both of these technologies manage their own 2nd-level caching 
 * strategies internally, and using this class as a parent would be considered redundant and probably less desireable
 * due to the redundancy overhead.  In this case (and other EIS technologies that use their own caching mechanisms),
 * it is probably better to implement the {@link org.jsecurity.session.support.eis.SessionDAO SessionDAO} interface
 * explicitly instead of using this class as a parent.
 *
 * <p>Raw JDBC-based implementations however would probably benefit from using this class as a parent and overriding
 * all the <tt>MemorySessionDAO</tt> parent methods as mentioned above.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class EhcacheSessionDAO extends MemorySessionDAO {

    private CacheManager manager;
    private boolean managerSetImplicitly = false;

    public EhcacheSessionDAO() {
        setCacheProvider( new EhCacheProvider() );
        setMaintainStoppedSessions( false );
    }

    public void setCacheManager( CacheManager cacheManager ) {
        this.manager = cacheManager;
    }

    public void init() {
        EhCacheProvider provider = (EhCacheProvider)this.cacheProvider;

        if ( manager != null ) {
            provider.setCacheManager( manager );
        }

        provider.init();

        if ( manager == null ) {
            setCacheManager( provider.getCacheManager() );
            managerSetImplicitly = true;
        }

        super.init();
    }

    public void onDestroy() {
        if ( managerSetImplicitly ) {
            setCacheManager( null );
            managerSetImplicitly = false;
        }
        if ( this.cacheProvider instanceof Destroyable ) {
            Destroyable destroyable = (Destroyable)this.cacheProvider;
            try {
                destroyable.destroy();
            } catch ( Exception e ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "Unable to cleanly destroy cacheProvider instance.  Ignoring (shutting down)..." );
                }
            }
        }
    }
}
