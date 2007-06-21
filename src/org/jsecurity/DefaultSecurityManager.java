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
import org.jsecurity.authz.module.support.AnnotationsModularAuthorizer;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.session.SessionManager;
import org.jsecurity.session.support.DefaultSessionFactory;
import org.jsecurity.session.support.DefaultSessionManager;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;

import java.io.Serializable;
import java.net.InetAddress;
import java.security.Principal;
import java.util.*;

/**
 * <p>Implementation of the {@link org.jsecurity.SecurityManager} interface that is based around
 * a set of security {@link org.jsecurity.realm.Realm}s.  This implementation delegates its authentication and
 * authorization operations to wrapped {@link Authenticator} and {@link Authorizer} instances.
 * It also provides some sensible defaults to simplify configuration.
 *
 * <p>This implementation is primarily a convenience mechanism that wraps both instances to consolidate
 * both behaviors into a single point of reference.  For most JSecurity users, this simplifies configuration and
 * tends to be a more convenient approach than referencing the <code>Authenticator</code> and <code>Authorizer</code>
 * instances seperately in their application code;  instead they only need to interact with a single
 * <tt>SecurityManager</tt> instance.
 *
 * <p>If an authenticator is not configured, a {@link org.jsecurity.authc.support.ModularRealmAuthenticator} is created using
 * the configured realms for the authenticator, (at least one
 * realm must be configured before {@link #init()} is called for this manager to function properly).</p>
 *
 * <p><b>Note:</b> Unless specified otherwise, the {@link #setAuthorizer Authorizer} property defaults to an
 * {@link org.jsecurity.authz.module.support.AnnotationsModularAuthorizer} instance to simplify configuration; if you
 * don't want to use JDK 1.5+ annotataions for authorization checks, you'll need to inject another implementation or 
 * programmatically interact with a subject's SecurityContext directly in code (ok, but not as 'clean').
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class DefaultSecurityManager implements SecurityManager, Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected transient final Log log = LogFactory.getLog( getClass() );

    /**
     * The authenticator that is delegated to for authentication purposes.
     */
    protected Authenticator authenticator;

    /**
     * The authorizer that is delegated to for authorization purposes.
     */
    protected Authorizer authorizer = null;

    protected SessionFactory sessionFactory;
    protected SessionManager sessionManager;

    private boolean sessionFactoryImplicitlyCreated = false;
    private boolean sessionManagerImplicitlyCreated = false;
    private boolean authenticatorImplicitlyCreated = false;
    private boolean authorizerImplicitlyCreated = false;

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
    public DefaultSecurityManager(){}

    /**
     * Supporting constructor that sets the required realms property.
     *
     * <p>Because this constructor does not accept a
     * <tt>SessionFactory</tt> or <tt>SessionManager</tt> argument (like others in this class), and therefore uses
     * the default <tt>init()</tt> logic to create a memory-based <tt>SessionFactory</tt>, it is not recommended that
     * this constructor is used in production environments, where file-based or RDBMS-based solutions are better
     * utilized.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager( List<Realm> realms ) {
        setRealms( realms );
        init();
    }

    /**
     * Supporting constructor that sets common properties and then automatically calls {@link #init()}.  Can be
     * used both inside and outside of IoC environments.
     * 
     * @param realms the Realm instances backing this SecurityManager
     * @param sessionFactory sessionFactory delegate instance - see {@link #setSessionFactory} for more info.
     */
    public DefaultSecurityManager( List<Realm> realms, SessionFactory sessionFactory ) {
        setRealms( realms );
        setSessionFactory( sessionFactory );
        init();
    }

    /**
     * Supporting constructor that sets common properties and then automatically calls {@link #init()}.  Can be
     * used both inside and outside of IoC environments.
     * @param realms the Realm instances backing this SecurityManager
     * @param sessionManager the sessionManager instance that will be used to construct an internal <tt>SessionFactory</tt>
     * instance - this is the recommended approach for most applications - see {@link #setSessionManager} for more info.
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
                    DefaultSessionManager sessionManager = new DefaultSessionManager();
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

    public void init() {

        if( realmMap == null || realmMap.isEmpty() ) {
            throw new IllegalStateException( "init() called but no realms have been configured " +
                "for this manager.  At least one realm needs to be configured on this manager." );
        }

        if( authenticator == null ) {
            ModularRealmAuthenticator realmAuthenticator = new ModularRealmAuthenticator( this, getAllRealms() );
            realmAuthenticator.init();
            authenticator = realmAuthenticator;
            authenticatorImplicitlyCreated = true;
        }

        if ( authorizer == null ) {
            authorizer = new AnnotationsModularAuthorizer();
            authorizerImplicitlyCreated = true;
        }
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
        }
        if ( sessionFactoryImplicitlyCreated ) {
            if ( sessionFactory instanceof Destroyable ) {
                destroy( (Destroyable)sessionFactory );
            }
        }
        if ( authorizerImplicitlyCreated ) {
            if ( authorizer instanceof Destroyable ) {
                destroy( (Destroyable)authorizer );
            }
        }
        if ( authenticatorImplicitlyCreated ) {
            if ( authenticator instanceof Destroyable ) {
                destroy( (Destroyable)authenticator );
            }
        }
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setAuthorizer(Authorizer authorizer) {
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
     * @see #setSessionManager
     *
     * @param sessionFactory delegate instance to use to support this manager's {@link #start} and {@link #getSession}
     * implementations.
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
     * @see #setSessionFactory
     *
     * @param sessionManager the <tt>SessionManager</tt> used to create an internal <tt>SessionFactory</tt> if one is
     * not already provided via configuration.
     */
    public void setSessionManager( SessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    /**
     * Sets the realms managed by this <tt>SecurityManager</tt> instance.
     * @param realms the realms managed by this <tt>SecurityManager</tt> instance.
     */
    public void setRealms(List<Realm> realms) {
        this.realmMap = new LinkedHashMap<String, Realm>( realms.size() );

        for( Realm realm : realms ) {

            if( realmMap.containsKey( realm.getName() ) ) {
                throw new IllegalArgumentException( "Two or more realms have a non-unique name ["
                        + realm.getName() + "].  All realms must have unique names.  Please configure these realms " +
                        "with unique names." );
            }

            realmMap.put( realm.getName(), realm );
        }
    }

    @SuppressWarnings( "unchecked" )
    public List<Realm> getAllRealms() {
        if( realmMap != null ) {
            return new ArrayList<Realm>( realmMap.values() );
        } else {
            return Collections.EMPTY_LIST;
        }
    }
    
    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Delegates to the authenticator for authentication.
     */
    public SecurityContext authenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        return authenticator.authenticate( authenticationToken );
    }

    /**
     * Delegates to the authorizer for autorization.
     */
    public boolean isAuthorized(SecurityContext context, AuthorizedAction action) {
        return authorizer.isAuthorized( context, action );
    }

    /**
     * Delegates to the authorizer for authorization.
     */
    public void checkAuthorization(SecurityContext context, AuthorizedAction action) throws AuthorizationException {
        authorizer.checkAuthorization( context, action );
    }


    /**
     * Retrieves the realm with the given name from the realm map or throws an exception if one
     * is not found.
     * @param realmName the name of the realm to be retrieved.
     * @return the realm to be retrieved.
     * @throws IllegalArgumentException if no realm is found with the given name.
     */
    public Realm getRealm(String realmName) {
        Realm realm = realmMap.get( realmName );
        if( realm == null ) {
            throw new IllegalArgumentException( "No realm found with name [" + realmName + "]" );
        } else {
            return realm;
        }
    }


    public boolean hasRole(Principal subjectIdentifier, String roleIdentifier) {
        boolean hasRole = false;
        for( Realm realm : getAllRealms() ) {
            if( realm.hasRole( subjectIdentifier, roleIdentifier ) ) {
                hasRole = true;
                break;
            }
        }
        return hasRole;
    }

    public boolean[] hasRoles(Principal subjectIdentifier, List<String> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];

        for( Realm realm : getAllRealms() ) {
            boolean realmHasRoles[] = realm.hasRoles( subjectIdentifier, roleIdentifiers );

            for( int i = 0; i < realmHasRoles.length; i++ ) {
                if( realmHasRoles[i] ) {
                    hasRoles[i] = true;
                }
            }
        }
        return hasRoles;
    }


    public boolean hasAllRoles(Principal subjectIdentifier, Collection<String> roleIdentifiers) {
        for( String roleIdentifier : roleIdentifiers ) {
            if( !hasRole( subjectIdentifier, roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }


    public boolean isPermitted(Principal subjectIdentifier, Permission permission) {
        for( Realm realm : getAllRealms() ) {
            if( realm.isPermitted( subjectIdentifier,  permission ) ) {
                return true;
            }
        }
        return false;
    }


    public boolean[] isPermitted(Principal subjectIdentifier, List<Permission> permissions) {
        boolean[] isPermitted = new boolean[permissions.size()];
        for( Realm realm : getAllRealms() ) {
            boolean realmIsPermitted[] = realm.isPermitted( subjectIdentifier, permissions );

            for( int i = 0; i < realmIsPermitted.length; i++ ) {
                if( realmIsPermitted[i] ) {
                    isPermitted[i] = true;
                }
            }
        }
        return isPermitted;
    }


    public boolean isPermittedAll(Principal subjectIdentifier, Collection<Permission> permissions) {
        for( Permission permission : permissions ) {
            if( !isPermitted( subjectIdentifier, permission ) ) {
                return false;
            }
        }
        return true;
    }


    public void checkPermission(Principal subjectIdentifier, Permission permission) throws AuthorizationException {
        if( !isPermitted( subjectIdentifier, permission ) ) {
            throw new AuthorizationException( "User does not have permission [" + permission.toString() + "]" );
        }
    }


    public void checkPermissions(Principal subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                checkPermission( subjectIdentifier, permission );
            }
        }
    }

    public void checkRole(Principal subjectIdentifier, String role) throws AuthorizationException {
        if( !hasRole( subjectIdentifier, role ) ) {
            throw new AuthorizationException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles(Principal subjectIdentifier, Collection<String> roles) throws AuthorizationException {
        if( roles != null ) {
            for( String role : roles ) {
                checkRole( subjectIdentifier, role );
            }
        }
    }


    public Session start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        ensureSessionFactory();
        return sessionFactory.start( hostAddress );
    }

    public Session getSession( Serializable sessionId ) throws InvalidSessionException, AuthorizationException {
        ensureSessionFactory();
        return sessionFactory.getSession( sessionId );
    }
}