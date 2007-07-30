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

package org.jsecurity.session.support.eis.support;

import org.jsecurity.cache.support.HashtableCacheProvider;
import org.jsecurity.session.Session;
import org.jsecurity.session.support.SimpleSession;
import org.jsecurity.util.ClassUtils;
import org.jsecurity.util.JavaEnvironment;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Random;

/**
 * Simple memory-based implementation of the SessionDAO.  It does not save session data to disk, so
 * this implementation is not recommended in production-quality recoverable environments
 * (i.e. those needing session state restored when a server restarts).
 *
 * <p>If you need session recovery in the event of a server failure or restart, consider using
 * a file-based or RDBMS-based implementation.
 *
 * @see org.jsecurity.session.support.eis.ehcache.EhcacheSessionDAO EhcacheSessionDAO
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class MemorySessionDAO extends AbstractCachingSessionDAO {

    private static final String VALID_JUG_CLASS_NAME = "org.safehaus.uuid.UUIDGenerator";
    private static final String RANDOM_NUM_GENERATOR_ALGORITHM_NAME = "SHA1PRNG";
    private Random randomNumberGenerator = null;

    public MemorySessionDAO() {
        setCacheProvider( new HashtableCacheProvider() );
        setMaintainStoppedSessions( true );
    }

    private Random getRandomNumberGenerator() {
        if ( randomNumberGenerator == null ) {
            if ( log.isWarnEnabled() ) {
                String msg = "On JDK 1.4 platforms and below, please ensure the JUG jar file is in the classpath for " +
                    "valid Session ID generation.  Defaulting to SecureRandom based id generation for now " +
                    "(NOT recommended for production systems - please add the JUG jar as soon as convenient).";
                log.warn( msg );
            }

            try {
                randomNumberGenerator = java.security.SecureRandom.getInstance( RANDOM_NUM_GENERATOR_ALGORITHM_NAME );
            } catch ( java.security.NoSuchAlgorithmException e ) {
                randomNumberGenerator = new java.security.SecureRandom();
            }
        }
        return randomNumberGenerator;
    }

    protected Serializable generateNewSessionId() {
        if ( JavaEnvironment.isAtLeastVersion15() ) {
            return java.util.UUID.randomUUID().toString();
        } else if ( ClassUtils.isAvailable( VALID_JUG_CLASS_NAME ) ) {
            //JUG library is available, lets use it to generate an ID:
            return org.safehaus.uuid.UUIDGenerator.getInstance().generateRandomBasedUUID().toString();
        } else {
            return Long.toString( getRandomNumberGenerator().nextLong() );
        }
    }

    protected Serializable doCreate( Session session ) {
        Serializable sessionId = generateNewSessionId();
        ((SimpleSession)session).setSessionId( sessionId );
        return sessionId;
    }

    protected Session doReadSession( Serializable sessionId ) {
        return null; //should never execute because this implementation relies on parent class to access cache, which
                     //is where all in-memory sessions reside.
    }

    protected void doUpdate(Session session) {
        //does nothing - parent class persists to in-memory cache.
    }

    protected void doDelete(Session session) {
        //does nothing - parent class removes from in-memory cache.
    }

    @SuppressWarnings({"unchecked"})
    public Collection<Session> getActiveSessions() {
        if ( activeSessions != null ) {
            Map sessionsMap = activeSessions.toMap();
            if ( sessionsMap != null && !sessionsMap.isEmpty() ) {
                return Collections.unmodifiableCollection( sessionsMap.values() );
            }
        }
        return Collections.EMPTY_LIST;
    }
}
