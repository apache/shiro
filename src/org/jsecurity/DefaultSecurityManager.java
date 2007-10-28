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
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.session.SessionManager;
import org.jsecurity.session.support.DefaultSessionFactory;
import org.jsecurity.session.support.DefaultSessionManager;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.JavaEnvironment;

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
 * <p>Finally, if a SessionFactory is not configured, one will be created based on internal {@link SessionManager}
 * instance.  The SessionManager too will be implicitly created if it also hasn't been injected.
 *
 * <p>In fact, the only absolute requirement for a <tt>DefaultSecurityManager</tt> instance to function properly is
 * that at least one Realm must be injected and then the {@link #init() init} method must be called before it is used.</p>
 *
 * @since 0.2
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class DefaultSecurityManager implements SecurityManager, CacheProviderAware, Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final String DEFAULT_PROPERTIES_REALM_FILE_PATH = "classpath:org/jsecurity/default-jsecurity-users.properties";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected transient final Log log = LogFactory.getLog( getClass() );

    protected Authenticator authenticator;
    private boolean authenticatorImplicitlyCreated = false;

    protected Authorizer authorizer = null;
    private boolean authorizerImplicitlyCreated = false;

    protected SessionFactory sessionFactory;
    private boolean sessionFactoryImplicitlyCreated = false;

    protected SessionManager sessionManager;
    private boolean sessionManagerImplicitlyCreated = false;

    protected CacheProvider cacheProvider = null;
    private boolean cacheProviderImplicitlyCreated = false;

    private Realm realm = null;
    private boolean realmImplicitlyCreated = false;

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

    /**
     * Supporting constructor that sets common properties and then automatically calls {@link #init()}.
     *
     * @param realms         the Realm instances backing this SecurityManager
     * @param sessionFactory sessionFactory delegate instance - see {@link #setSessionFactory} for more info.
     */
    public DefaultSecurityManager( List<Realm> realms, SessionFactory sessionFactory ) {
        setRealms( realms );
        setSessionFactory( sessionFactory );
        init();
    }

    /**
     * Supporting constructor that sets common properties and then automatically calls {@link #init()}.
     *
     * @param realms         the Realm instances backing this SecurityManager
     * @param sessionManager the sessionManager instance that will be used to construct an internal <tt>SessionFactory</tt>
     *                       instance - see {@link #setSessionManager} for more info.
     */
    public DefaultSecurityManager( List<Realm> realms, SessionManager sessionManager ) {
        setRealms( realms );
        setSessionManager( sessionManager );
        init();
    }


    protected void ensureSessionFactory() {
        if ( this.sessionFactory == null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "No delegate SessionFactory instance has been set as a property of this class.  Defaulting " +
                    "to a SessionFactory instance backed by a SessionManager implementation..." );
            }

            //since a SessionManager can be lazily created when a session is first requested, we have to account for
            //the race condition when two sessions are requested at almost the exact same time - we want to ensure
            //that only one SessionManager is created due to the quartz and ehcache initialization overhead and to
            //avoid more than one SessionValidationScheduler from validating sessions too often.  So, we
            //synchronize on this object to ensure the implicit SessionManager instance creation only ever occurs once.
            synchronized ( this ) {
                if ( this.sessionManager == null ) {
                    if ( log.isInfoEnabled() ) {
                        log.info( "No SessionManager instance has been set as a property of this class.  " +
                            "Defaulting to the default SessionManager implementation." );
                    }
                    
                    initCacheProvider();

                    DefaultSessionManager sessionManager = new DefaultSessionManager();
                    sessionManager.setCacheProvider( getCacheProvider() );
                    setSessionManager( sessionManager );
                    sessionManagerImplicitlyCreated = true;
                    sessionManager.init();
                } else {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "Using configured SessionManager [" + sessionManager + "] to construct the default " +
                            "SessionFactory delegate instance." );
                    }
                }
            }

            DefaultSessionFactory sessionFactory = new DefaultSessionFactory();
            setSessionFactory( sessionFactory );
            sessionFactory.setSessionManager( sessionManager );
            sessionFactoryImplicitlyCreated = true;
            sessionFactory.init();
        }
    }

    protected void initCacheProvider() {
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
                    String msg = "Constructing default CacheProvider using an in-memory HashTable.  This is " +
                        "NOT RECOMMENDED for production environments.  Please ensure ehcache.jar is in the classpath " +
                        "and JSecurity will automatically use a production-quality CacheProvider implementation, or " +
                        "you may alternatively provide your own via the #setCacheProvider method.";
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

            PropertiesRealm propsRealm = null;

            try {
                propsRealm = new PropertiesRealm();
                propsRealm.init();
            } catch ( Exception e ) {
                destroy( propsRealm );
                if ( log.isInfoEnabled() ) {
                    log.info( "Unable to find jsecurity-users.properties in the root of the classpath.  Defaulting " +
                        "to a PropertiesRealm based on JSecurity's failsafe properties file " +
                        "(Guest user only)" );
                }
                propsRealm = new PropertiesRealm();
                propsRealm.setFilePath( DEFAULT_PROPERTIES_REALM_FILE_PATH );
                propsRealm.init();
            }

            setRealm( propsRealm );
            this.realm = propsRealm;
            this.realmImplicitlyCreated = true;
        }
    }
    protected void initAuthenticator() {
        if ( this.authenticator == null ) {
            ModularRealmAuthenticator mra = new ModularRealmAuthenticator();
            mra.setRealms( getAllRealms() );

            DelegatingSecurityContextFactory scFactory = new DelegatingSecurityContextFactory( this );
            mra.setSecurityContextFactory( scFactory );

            authenticatorImplicitlyCreated = true;
            setAuthenticator( mra );
            mra.init();
        }
    }
    protected void initAuthorizer() {
        if ( authorizer == null ) {
            ModularRealmAuthorizer mra = new ModularRealmAuthorizer();
            mra.setRealms( getAllRealms() );
            authorizerImplicitlyCreated = true;
            setAuthorizer( mra );
            mra.init();
        }
    }
    public void init() {
        ensureRealms();
        initAuthenticator();
        initAuthorizer();
    }

    private void destroy( Destroyable d ) {
        try {
            d.destroy();
        } catch ( Exception e ) {
            if ( log.isDebugEnabled() ) {
                String msg = "Unable to cleanly destroy implicitly created instance [" + d + "].";
                log.debug( msg, e );
            }
        }
    }

    public void destroy() {
        if ( sessionManagerImplicitlyCreated ) {
            if ( sessionManager instanceof Destroyable ) {
                destroy( (Destroyable)sessionManager );
            }
            sessionManager = null;
            sessionManagerImplicitlyCreated = false;
        }
        if ( sessionFactoryImplicitlyCreated ) {
            if ( sessionFactory instanceof Destroyable ) {
                destroy( (Destroyable)sessionFactory );
            }
            sessionFactory = null;
            sessionFactoryImplicitlyCreated = false;
        }
        if ( authorizerImplicitlyCreated ) {
            if ( authorizer instanceof Destroyable ) {
                destroy( (Destroyable)authorizer );
            }
            authorizer = null;
            authorizerImplicitlyCreated = false;
        }
        if ( authenticatorImplicitlyCreated ) {
            if ( authenticator instanceof Destroyable ) {
                destroy( (Destroyable)authenticator );
            }
            authenticator = null;
            authenticatorImplicitlyCreated = false;
        }
        if ( cacheProviderImplicitlyCreated ) {
            if ( cacheProvider instanceof Destroyable ) {
                destroy( (Destroyable)cacheProvider );
            }
            cacheProvider = null;
            cacheProviderImplicitlyCreated = false;
        }
        if ( realmImplicitlyCreated ) {
            if ( realm instanceof Destroyable ) {
                destroy( (Destroyable)realm );
                realm = null;
                realmImplicitlyCreated = false;
            }
        }
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
     * <p><b>N.B.</b>: The internal delegate instance can be set by this method, but it is usually a good idea
     * <em>not</em> to set this property and instead set a <tt>SessionManager</tt> instance via the
     * {@link #setSessionManager} method.  Then this class implementation will automatically create a
     * <tt>SessionFactory</tt> during the {@link #init} phase.
     *
     * <p>However, if <em>neither</em> this property or the {@link #setSessionManager sessionManager} properties are
     * set, this implementation will create sensible defaults for both properties automatically during
     * {@link #init()} execution.
     *
     * @param sessionFactory delegate instance to use to support this manager's {@link #start} and {@link #getSession}
     *                       implementations.
     * @see #setSessionManager
     */
    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    /**
     * Used to construct a default internal {@link SessionFactory} delegate instance if one is not explicitly set
     * in configuration via the {@link #setSessionFactory} method.
     *
     * <p>If a <tt>SessionFactory</tt> instance <em>is</em> set via {@link #setSessionFactory}, then this property is
     * ignored.
     *
     * <p><b>N.B.</b>: It is usually a good idea to set this property and <em>not</em> set the <tt>SessionFactory</tt>
     * instance explicitly unless you have a good reason to do so.
     *
     * @param sessionManager the <tt>SessionManager</tt> used to create an internal <tt>SessionFactory</tt> if one is
     *                       not already provided via configuration.
     * @see #setSessionFactory
     */
    public void setSessionManager( SessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    /**
     * Convenience method for applications with a single realm that merely wraps the realm in a list and then invokes
     * the {@link #setRealms} method.
     *
     * @param realm the realm to set for a single-realm application.
     * @since 0.2
     */
    public void setRealm( Realm realm ) {
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

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

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