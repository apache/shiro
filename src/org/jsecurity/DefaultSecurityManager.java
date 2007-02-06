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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.support.ModularRealmAuthenticator;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.authz.module.support.AnnotationsModularAuthorizer;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.session.Session;
import org.jsecurity.session.InvalidSessionException;

import java.security.Permission;
import java.security.Principal;
import java.util.*;
import java.net.InetAddress;
import java.io.Serializable;

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
 * the configured realms for the authenticator.  At least one
 * realm must be configured before {@link #init()} is called for this manager to function properly.</p>
 * <p><b>Note:</b> <ol><li>Unless specified otherwise, the {@link #setAuthorizer Authorizer} property defaults to an
 * {@link org.jsecurity.authz.module.support.AnnotationsModularAuthorizer} instance to simplify configuration; if you
 * don't want to use JDK 1.5+ annotataions for authorization checks, you'll need to inject another implementation or 
 * programmatically interact with a subject's SecurityContext directly in code (ok, but not as 'clean').</li>
 * <li>There is <strong>no default</strong> {@link #setAuthenticator Authenticator} created by this
 * <code>SecurityManager</code> abstract implementation, as it is expected to be
 * specified by Dependency Injection or by subclass implementations.</li></ol>
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class DefaultSecurityManager implements SecurityManager {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The authenticator that is delegated to for authentication purposes.
     */
    protected Authenticator authenticator;

    /**
     * The authorizer that is delegated to for authorization purposes.
     */
    protected Authorizer authorizer = new AnnotationsModularAuthorizer();

    protected SessionFactory sessionFactory;

    /**
     * A map from realm name to realm for all realms managed by this manager.
     */
    private Map<String, Realm> realmMap;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public void init() {

        if( realmMap == null || realmMap.isEmpty() ) {
            throw new IllegalStateException( "init() called but no realms have been configured " +
                "for this manager.  At least one realm needs to be configured on this manager." );
        }

        if ( sessionFactory == null ) {
            throw new IllegalStateException( "init() called but no SessionFactory has been configured for this " +
                    "SecurityManager.  An underlying delegate instance of SessionFactory must be set." );
        }

        if( authenticator == null ) {
            ModularRealmAuthenticator realmAuthenticator = new ModularRealmAuthenticator( this, getAllRealms() );
            realmAuthenticator.init();
            authenticator = realmAuthenticator;
        }
    }

    public void destroy() { //default implementation does nothing
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

    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    /**
     * Sets the realms managed by this manager.
     * @param realms the realms that should be managed by this manager.
     */
    public void setRealms(List<Realm> realms) {
        this.realmMap = new LinkedHashMap<String, Realm>( realms.size() );

        for( Realm realm : realms ) {

            if( realmMap.containsKey( realm.getName() ) ) {
                throw new IllegalArgumentException( "Two or more realmMap have a non-unique name [" + realm.getName() + "].  All " +
                    "realmMap must have unique names.  Please configure these realmMap with unique names." );
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


    public Session start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        return sessionFactory.start( hostAddress );
    }

    public Session getSession( Serializable sessionId ) throws InvalidSessionException, AuthorizationException {
        return sessionFactory.getSession( sessionId );
    }
}