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
import java.util.Random;

/**
 * Simple memory-based implementation of the SessionDAO that relies on its configured
 * {@link #setCacheProvider CacheProvider} for Session caching and in-memory persistence.
 *
 * <p><b>PLEASE NOTE</b> the default CacheProvider internal to this implementation is a
 * {@link HashtableCacheProvider HashtableCacheProvider}, which IS NOT RECOMMENDED for production environments.
 *
 * <p>If you
 * want to use the MemorySessionDAO in production environments, such as those that require session data to be
 * recoverable in case of a server restart, you should do one of two things (or both):
 *
 * <ul>
 *   <li>Configure it with a production-quality CacheProvider. The
 * {@link org.jsecurity.cache.ehcache.EhCacheProvider EhCacheProvider} is one such provider.  It is not used by default
 * to prevent a forced runtime dependency on ehcache.jar that may not be required in many environments)</li><br/>
 *   <li>If you need session information beyond their transient start/stop lifetimes, you should subclass this one and
 * override the <tt>do*</tt> methods to perform CRUD operations using an EIS-tier API (e.g. Hibernate/JPA/JCR/etc).
 *   This class implementation does not retain sessions after they have been stopped or expired, so you would need to
 * override these methods to ensure Sessions can be accessed beyond JSecurity's needs.</li>
 * </ul>
 *
 * @since 0.1
 *
 * @author Les Hazlewood
 */
public class MemorySessionDAO extends CachingSessionDAO {

    private static final String VALID_JUG_CLASS_NAME = "org.safehaus.uuid.UUIDGenerator";
    private static final String RANDOM_NUM_GENERATOR_ALGORITHM_NAME = "SHA1PRNG";
    private Random randomNumberGenerator = null;

    public MemorySessionDAO() {
        setCacheProvider( new HashtableCacheProvider() );
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
        assignSessionId( session, sessionId );
        return sessionId;
    }

    protected void assignSessionId( Session session, Serializable sessionId ) {
        ((SimpleSession)session).setSessionId( sessionId );
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
}
