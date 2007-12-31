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
package org.jsecurity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.support.ModularRealmAuthenticator;
import org.jsecurity.authz.*;
import org.jsecurity.authz.support.ModularRealmAuthorizer;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
import org.jsecurity.cache.ehcache.EhCacheProvider;
import org.jsecurity.cache.support.HashtableCacheProvider;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.factory.support.DelegatingSecurityContextFactory;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.support.file.PropertiesRealm;
import org.jsecurity.session.*;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.SessionEventNotifier;
import org.jsecurity.session.support.DefaultSessionFactory;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.JavaEnvironment;
import org.jsecurity.util.LifecycleUtils;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.*;


/**
 * <p>The JSecurity framework's default implementation of the {@link org.jsecurity.SecurityManager} interface,
 * based around a set of security {@link org.jsecurity.realm.Realm}s.  This implementation delegates its authentication,
 * authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link SessionFactory SessionFactory} instances respectively.
 * It also provides some sensible defaults to simplify configuration.</p>
 *
 * <p>This implementation is primarily a convenience mechanism that wraps these three instances to consolidate
 * all behaviors into a single point of reference.  For most JSecurity users, this simplifies configuration and
 * tends to be a more convenient approach than referencing <code>Authenticator</code>, <code>Authorizer</code>, and
 * <tt>SessionFactory</tt> instances seperately in their application code;  instead they only need to interact with a
 * single <tt>SecurityManager</tt> instance.</p>
 *
 * <p>If an authenticator is not configured, a {@link org.jsecurity.authc.support.ModularRealmAuthenticator} is created
 * using the configured realms.  Similarly, if an authorizer is not configured, a {@link ModularRealmAuthorizer}
 * instance will be created using the configured realms.
 *
 * <p>Finally, if a SessionFactory is not configured, one will be created as determined by the
 * {@link #isLazySessions() lazySessions} property.
 *
 * <p>In fact, the only absolute requirement for a <tt>DefaultSecurityManager</tt> instance to function properly is
 * that at least one Realm must be injected and then the {@link #init() init} method must be called before it is used.</p>
 *
 * @since 0.2
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class DefaultSecurityManager implements SecurityManager, SessionEventNotifier, CacheProviderAware, Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected transient final Log log = LogFactory.getLog( getClass() );

    protected CacheProvider cacheProvider = null;
    private boolean cacheProviderImplicitlyCreated = false;

    protected Authenticator authenticator;
    private boolean authenticatorImplicitlyCreated = false;

    protected Authorizer authorizer = null;
    private boolean authorizerImplicitlyCreated = false;

    protected SessionFactory sessionFactory;
    private boolean sessionFactoryImplicitlyCreated = false;

    private Realm realm = null;
    private boolean realmImplicitlyCreated = false;

    private boolean lazySessions = true;

    /**
     * A map from realm name to realm for all realms managed by this manager.
     */
    private Map<String, Realm> realmMap;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public DefaultSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application (automatically calls {@link #init()} before returning).
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public DefaultSecurityManager( Realm singleRealm ) {
        setRealm( singleRealm );
        init();
    }

    /**
     * Supporting constructor that sets the required realms property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager( List<Realm> realms ) {
        setRealms( realms );
        init();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticator( Authenticator authenticator ) {
        this.authenticator = authenticator;
    }

    public void setAuthorizer( Authorizer authorizer ) {
        this.authorizer = authorizer;
    }

    /**
     * Sets the underlying delegate {@link SessionFactory} instance that will be used to support calls to this
     * manager's {@link #start} and {@link #getSession} calls.
     *
     * <p>This <tt>SecurityManager</tt> implementation does not provide logic to support the inherited
     * <tt>SessionFactory</tt> interface, but instead delegates these calls to an internal
     * <tt>SessionFactory</tt> instance.
     *
     * <p>If a <tt>SessionFactory</tt> instance is not set, a default one will be automatically created and
     * initialized based on the {@link #isLazySessions() lazySessions} property.
     *
     * @param sessionFactory delegate instance to use to support this manager's {@link #start} and {@link #getSession}
     *                       implementations.
     */
    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    public SessionFactory getSessionFactory() {
        return this.sessionFactory;
    }

    public void add( SessionEventListener listener ) {
        ensureSessionFactory();
        assertSessionFactoryEventListenerSupport( this.sessionFactory );
        ((SessionEventNotifier)this.sessionFactory).add( listener );
    }

    public boolean remove( SessionEventListener listener ) {
        return (this.sessionFactory instanceof SessionEventNotifier ) &&
               ((SessionEventNotifier) this.sessionFactory).remove(listener);
    }

    /**
     * Convenience method for applications with a single realm that merely wraps the realm in a list and then invokes
     * the {@link #setRealms} method.
     *
     * @param realm the realm to set for a single-realm application.
     * @since 0.2
     */
    public void setRealm( Realm realm ) {
        if ( realm == null ) {
            throw new IllegalArgumentException( "Realm argument cannot be null" );
        }
        List<Realm> realms = new ArrayList<Realm>( 1 );
        realms.add( realm );
        setRealms( realms );
    }

    /**
     * Sets the realms managed by this <tt>SecurityManager</tt> instance.
     *
     * @param realms the realms managed by this <tt>SecurityManager</tt> instance.
     */
    public void setRealms( List<Realm> realms ) {
        if ( realms == null ) {
            throw new IllegalArgumentException( "Realms collection argument cannot be null." );
        }
        if ( realms.isEmpty() ) {
            throw new IllegalArgumentException( "Realms collection argument cannot be empty." );
        }
        this.realmMap = new LinkedHashMap<String, Realm>( realms.size() );

        for ( Realm realm : realms ) {

            if ( realmMap.containsKey( realm.getName() ) ) {
                throw new IllegalArgumentException( "Two or more realms have a non-unique name ["
                    + realm.getName() + "].  All realms must have unique names.  Please configure these realms " +
                    "with unique names." );
            }

            realmMap.put( realm.getName(), realm );
        }
    }

    @SuppressWarnings( "unchecked" )
    public Collection<Realm> getAllRealms() {
        if ( realmMap != null ) {
            return new ArrayList<Realm>( realmMap.values() );
        } else {
            return Collections.EMPTY_LIST;
        }
    }

    /**
     * Returns the default CacheProvider used by this SecurityManager and any of the caching-aware children components
     * implicitly created
     * @return the cacheProvider used by this SecurityManager and any of its caching-aware implicitly created children components.
     */
    public CacheProvider getCacheProvider() {
        return cacheProvider;
    }

    public void setCacheProvider( CacheProvider cacheProvider ) {
        this.cacheProvider = cacheProvider;
    }

    /**
     * Returns whether or not the SessionFactory infrastructure will be lazily initialized upon the first session
     * request.  If this returns <tt>true</tt>, the SessionFactory infrastructure will not be initialized until the
     * first request for a session occurs.  If <tt>false</tt>, the SessionFactory infrastructure will be
     * eagerly initialized when this SecurityManager instance is initialized.
     *
     * <p>The default value is <strong><tt>true</tt></strong> to slightly increase application startup times and
     * reduce overhead when not using Sessions.  If you require JSecurity Sessions in your app (as would be the
     * case when not a pure web-app or Session state must be accessible by many clients) it is usually better to set
     * this value to <tt>false</tt> to eagerly initialize, ensuring initial session access will be fast and any
     * configuration settings will be verified on application startup instead of being discovered at a later point.
     *
     * @return <tt>true</tt> if the SessionFactory infrastructure will be lazily initialized based on the first
     * request for a session, <tt>false</tt> if it will be eagerly initialized at the same time as this SecurityManager.
     */
    public boolean isLazySessions() {
        return lazySessions;
    }

    /**
     * Sets whether or not the SessionFactory infrastructure will be lazily initialized upon the first session
     * request.  If this value is <tt>true</tt>, the SessionFactory infrastructure will not be initialized until the
     * first request for a session occurs.  If <tt>false</tt>, the SessionFactory infrastructure will be
     * eagerly initialized when this SecurityManager instance is initialized.
     *
     * <p>The default value is <strong><tt>true</tt></strong> to slightly increase application startup times and
     * reduce overhead when not using Sessions.  If you require JSecurity Sessions in your app (as would be the
     * case when not a pure web-app or Session state must be accessible by many clients) it is usually better to set
     * this value to <tt>false</tt> to eagerly initialize, ensuring initial session access will be fast and any
     * configuration settings will be verified on application startup instead of being discovered at a later point.
     *
     * @param lazySessions value indicating if the SessionFactory infrastructure will be lazily initialized
     * (value of true) or eagerly initialized (value of false)
     */
    public void setLazySessions(boolean lazySessions) {
        this.lazySessions = lazySessions;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    private void assertSessionFactoryEventListenerSupport( SessionFactory factory ) {
        if ( !(factory instanceof SessionEventNotifier) ) {
            String msg = "SessionEventListener registration failed:  The underlying SessionFactory instance of " +
                    "type [" + factory.getClass().getName() + "] does not implement the " +
                    SessionEventNotifier.class.getName() + " interface and therefore cannot support " +
                    "runtime SessionEvent propagation.";
            throw new IllegalStateException( msg );
        }
    }

    protected SessionFactory createSessionFactory() {
        DefaultSessionFactory sessionFactory = new DefaultSessionFactory();
        sessionFactory.setCacheProvider( getCacheProvider() );
        sessionFactory.init();
        return sessionFactory;
    }

    protected void ensureSessionFactory() {
        if ( this.sessionFactory == null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "No delegate SessionFactory instance has been set as a property of this class.  Creating a " +
                        "default SessionFactory implementation..." );
            }
            SessionFactory sessionFactory = createSessionFactory();
            setSessionFactory( sessionFactory );
            sessionFactoryImplicitlyCreated = true;
        }
    }

    protected synchronized void ensureCacheProvider() {
        //only create one if one hasn't been explicitly set by the instantiator
        CacheProvider cacheProvider = getCacheProvider();
        if ( cacheProvider == null ) {
            if ( JavaEnvironment.isEhcacheAvailable() ) {
                if ( log.isDebugEnabled() ) {
                    String msg = "Initializing default CacheProvider using EhCache.";
                    log.debug( msg );
                }
                EhCacheProvider provider = new EhCacheProvider();
                provider.init();
                cacheProvider = provider;
            } else {
                if ( log.isWarnEnabled() ) {
                    String msg = "Instantiating default CacheProvider which will create in-memory HashTable caches.  " +
                        "This is NOT RECOMMENDED for production environments.  Please ensure ehcache.jar is in the " +
                        "classpath and JSecurity will automatically use a production-quality CacheProvider " +
                        "implementation, or you may alternatively provide your own via the #setCacheProvider method.";
                    log.warn( msg );
                }
                cacheProvider = new HashtableCacheProvider();
            }
            cacheProviderImplicitlyCreated = true;
            setCacheProvider( cacheProvider );
        }
    }

    protected void ensureRealms() {
        if ( realmMap == null || realmMap.isEmpty() ) {

            if ( log.isInfoEnabled() ) {
                log.info( "No realms set - creating default PropertiesRealm (not recommended for production)." );
            }

            PropertiesRealm propsRealm = new PropertiesRealm();
            propsRealm.setCacheProvider( getCacheProvider() );
            propsRealm.init();

            setRealm( propsRealm );
            this.realm = propsRealm;
            this.realmImplicitlyCreated = true;
        }
    }

    protected void ensureAuthenticator() {
        if ( this.authenticator == null ) {
            ModularRealmAuthenticator mra = new ModularRealmAuthenticator();
            mra.setRealms( getAllRealms() );

            DelegatingSecurityContextFactory scFactory = new DelegatingSecurityContextFactory( this );
            mra.setSecurityContextFactory( scFactory );

            mra.init();

            authenticatorImplicitlyCreated = true;
            setAuthenticator( mra );
        }
    }

    protected void ensureAuthorizer() {
        if ( authorizer == null ) {
            ModularRealmAuthorizer mra = new ModularRealmAuthorizer();
            mra.setRealms( getAllRealms() );
            mra.init();

            authorizerImplicitlyCreated = true;
            setAuthorizer( mra );
        }
    }

    public void init() {
        ensureCacheProvider();
        ensureRealms();
        ensureAuthenticator();
        ensureAuthorizer();
        if ( !isLazySessions() ) {
            //start SessionFactory infrastructure now
            ensureSessionFactory();
        }
    }

    public void destroy() {
        if ( sessionFactoryImplicitlyCreated ) {
            LifecycleUtils.destroy( sessionFactory );
            sessionFactory = null;
            sessionFactoryImplicitlyCreated = false;
        }
        if ( authorizerImplicitlyCreated ) {
            LifecycleUtils.destroy( authorizer );
            authorizer = null;
            authorizerImplicitlyCreated = false;
        }
        if ( authenticatorImplicitlyCreated ) {
            LifecycleUtils.destroy( authenticator );
            authenticator = null;
            authenticatorImplicitlyCreated = false;
        }
        if ( realmImplicitlyCreated ) {
            LifecycleUtils.destroy( realm );
            realm = null;
            realmImplicitlyCreated = false;
        }
        if ( cacheProviderImplicitlyCreated ) {
            LifecycleUtils.destroy( cacheProvider );
            cacheProvider = null;
            cacheProviderImplicitlyCreated = false;
        }
    }

    /**
     * Delegates to the authenticator for authentication.
     */
    public SecurityContext authenticate( AuthenticationToken authenticationToken ) throws AuthenticationException {
        return authenticator.authenticate( authenticationToken );
    }

    public boolean supports( AuthorizedAction action ) {
        return authorizer.supports( action );
    }

    /**
     * Delegates to the authorizer for autorization.
     */
    public boolean isAuthorized( Object subjectIdentity, AuthorizedAction action ) {
        return authorizer.isAuthorized( subjectIdentity, action );
    }

    /**
     * Delegates to the authorizer for authorization.
     */
    public void checkAuthorization( Object subjectIdentity, AuthorizedAction action ) throws AuthorizationException {
        authorizer.checkAuthorization( subjectIdentity, action );
    }

    /**
     * Retrieves the realm with the given name from the realm map or throws an exception if one
     * is not found.
     *
     * @param realmName the name of the realm to be retrieved.
     * @return the realm to be retrieved.
     * @throws IllegalArgumentException if no realm is found with the given name.
     */
    public Realm getRealm( String realmName ) {
        return realmMap.get( realmName );
    }

    public boolean hasRole( Object subjectIdentifier, String roleIdentifier ) {
        return authorizer.hasRole( subjectIdentifier, roleIdentifier );
    }

    public boolean[] hasRoles( Object subjectIdentifier, List<String> roleIdentifiers ) {
        return authorizer.hasRoles( subjectIdentifier, roleIdentifiers );
    }

    public boolean hasAllRoles( Object subjectIdentifier, Collection<String> roleIdentifiers ) {
        return authorizer.hasAllRoles( subjectIdentifier, roleIdentifiers );
    }

    public boolean isPermitted( Object subjectIdentifier, Permission permission ) {
        return authorizer.isPermitted( subjectIdentifier, permission );
    }

    public boolean[] isPermitted( Object subjectIdentifier, List<Permission> permissions ) {
        return authorizer.isPermitted( subjectIdentifier, permissions );
    }

    public boolean isPermittedAll( Object subjectIdentifier, Collection<Permission> permissions ) {
        return authorizer.isPermittedAll( subjectIdentifier, permissions );
    }

    public void checkPermission( Object subjectIdentifier, Permission permission ) throws AuthorizationException {
        authorizer.checkPermission( subjectIdentifier, permission );
    }

    public void checkPermissions( Object subjectIdentifier, Collection<Permission> permissions ) throws AuthorizationException {
        authorizer.checkPermissions( subjectIdentifier, permissions );
    }

    public void checkRole( Object subjectIdentifier, String role ) throws AuthorizationException {
        authorizer.checkRole( subjectIdentifier, role );
    }

    public void checkRoles( Object subjectIdentifier, Collection<String> roles ) throws AuthorizationException {
        authorizer.checkRoles( subjectIdentifier, roles );
    }

    public Session start( InetAddress hostAddress ) throws HostUnauthorizedException, IllegalArgumentException {
        ensureSessionFactory();
        return sessionFactory.start( hostAddress );
    }

    public Session getSession( Serializable sessionId ) throws InvalidSessionException, AuthorizationException {
        ensureSessionFactory();
        return sessionFactory.getSession( sessionId );
    }
}