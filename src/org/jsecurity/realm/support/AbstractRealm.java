/*
 * Copyright (C) 2006 Jeremy Haile
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

package org.jsecurity.realm.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.CredentialMatcher;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.NoAuthorizationInfoFoundException;
import org.jsecurity.realm.Realm;

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;

/**
 * <p>An abstract implementation of the {@link Realm} interface that allows
 * subclasses to simply implement the {@link AbstractRealm#doGetAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)}
 * and {@link AbstractRealm#getAuthorizationInfo(java.security.Principal)} methods.</p>
 *
 * <p>This realm also returns the fully qualified class name of the realm implementation as the
 * realm's unique name - but a name can be specified by the {@link #setName(String)} method.  This is necessary
 * if more than one realm of the same type is used in an application.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public abstract class AbstractRealm implements Realm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logger.
     */
    protected transient final Log log = LogFactory.getLog( getClass() );

    /**
     * The name of this realm, or null if the fully-qualified class name should be returned
     * as the realm name.
     */
    private String name;

    /**
     * Password matcher used to determine if the provided password matches
     * the password stored in the data store.  Only utilized if non-null.
     */
    protected CredentialMatcher credentialMatcher = null;

    /**
     * The class that this realm supports for authentication tokens.  This is used by the
     * default implementation of the {@link #supports(Class)} method to determine whether or not the
     * given authentication token is supported by this realm.
     */
    protected Class<? extends AuthenticationToken> authenticationTokenClass = UsernamePasswordToken.class;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setName(String name) {
        this.name = name;
    }

    public CredentialMatcher getCredentialMatcher() {
        return credentialMatcher;
    }

    /**
     * Sets the CrendialMatcher implementation to use to verify submitted credentials with those stored in the system
     * for a given authentication attempt.  The implementation of this matcher can be switched via configuration to
     * support any number of schemes, including plain text password comparison, digest/hashing comparisons, and others.
     *
     * <p>If not set, no crendtial checking will occur.
     *
     * @param credentialMatcher the matcher to use.
     */
    public void setCredentialMatcher(CredentialMatcher credentialMatcher) {
        this.credentialMatcher = credentialMatcher;
    }

    /**
     * Returns the authenticationToken class supported by this module.
     *
     * <p>The default value is <tt>{@link UsernamePasswordToken UsernamePasswordToken.class}</tt>, since
     * about 90% of modules use username/password authentication, regardless of their protocol (e.g. over jdbc, ldap,
     * kerberos, http, etc).
     *
     * <p>Subclasses must override this method if they won't support <tt>UsernamePasswordToken</tt> authentications and
     * they haven't already overridden the {@link #supports} method.
     *
     * @return the authenticationToken class supported by this module.
     *
     * @see #setAuthenticationTokenClass
     */
    public Class getAuthenticationTokenClass() {
        return authenticationTokenClass;
    }

    /**
     * Sets the authenticationToken class supported by this module.
     *
     * @param authenticationTokenClass the class of authentication token instances supported by this module.
     */
    public void setAuthenticationTokenClass(Class<? extends AuthenticationToken> authenticationTokenClass) {
        this.authenticationTokenClass = authenticationTokenClass;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    protected abstract AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException;


    /**
     * This method should be implemented by subclasses to retrieve authorization information for
     * the given principal.
     * @param principal the principal that authorization information should be retrieved for.
     * @return an {@link AuthorizationInfo} object encapsulating the authorization information
     * associated with the given principal.
     * @throws NoAuthorizationInfoFoundException if authorization information could not
     * be found for the given principal.
     */
    protected abstract AuthorizationInfo getAuthorizationInfo(Principal principal);

    /**
     * Convenience implementation that returns
     * <tt>getAuthenticationTokenClass().isAssignableFrom( tokenClass );</tt>.  Can be overridden
     * by subclasses for more complex token type checking.
     * <p>Most implementations will only need to set a different class via
     * {@link #setAuthenticationTokenClass}, as opposed to overriding this method.
     *
     * @param tokenClass the class of the authenticationToken being submitted for authentication.
     * @return true if this authentication module "understands" how to process submissions for the submitted token
     * instances of the class, false otherwise.
     */
    public boolean supports(Class tokenClass) {
        return getAuthenticationTokenClass().isAssignableFrom( tokenClass );
    }

    /**
     * Primarily used to acquire a string to display in exceptions and logging.  Default implementation
     * returns a value based on info.getPrincipal();
     *
     * <p>If overridding, be careful to not include any private credentials (such as passwords or private keys) if this
     * information should not show up in log entries or error messages.
     * @param info account info after a successful authentication attempt.
     * @return string representation of the given info that can be used in exceptions and logging.
     */
    protected String displayName( AuthenticationInfo info ) {
        Principal p = info.getPrincipal();
        if ( p != null ) {
            return p.toString();
        } else {
            return info.toString();
        }
    }

    protected boolean isAccountLocked( AuthenticationInfo info ) {
        return info.isAccountLocked();
    }

    protected boolean isCredentialsExpired( AuthenticationInfo info ) {
        return info.isCredentialsExpired();
    }

    public final AuthenticationInfo getAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = doGetAuthenticationInfo( token );
        } catch( AuthenticationException ae ) {
            //the subclass already formulated a meaningful AuthenticationException, just let it
            //propagate:
            throw ae;
        } catch (Throwable t) {
            //probably unexpected exception.  Wrap and propagate:
            final String message = "AuthenticationToken [" + token + "] could not be authenticated because an error " +
                    "occurred during authentication.";
            if( log.isErrorEnabled() ) {
                log.error( message, t );
            }
            throw new AuthenticationException( message, t );
        }

        if( info == null ) {
            String msg = "No account information found for submitted authentication token [" + token + "]";
            throw new UnknownAccountException( msg );
        }

        if( isAccountLocked( info ) ) {
            throw new LockedAccountException( "Account [" + displayName( info ) + "] is locked." );
        }

        if( isCredentialsExpired( info ) ) {
            String msg = "The credentials for account [" + displayName( info ) + "] are expired";
            throw new ExpiredCredentialException( msg );
        }

        CredentialMatcher cm = getCredentialMatcher();
        if ( cm != null ) {
            if ( !cm.doCredentialsMatch( token.getCredentials(), info.getCredentials() ) ) {
                String msg = "The credentials provided for account [" + token +
                             "] did not match the expected credentials.";
                throw new IncorrectCredentialException( msg );
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No CredentialMatcher configured.  Credential comparison check has been bypassed." );
            }
        }

        return info;
    }

    /**
     * The default implementation of getName() returns the fully-qualified class name if no
     * name has been specified for this Realm.  If more than one realm of a
     * particular Realm class is used in an application, the name must be
     * manually specified.
     * @return the name associated with this realm, or the fully-qualified class name
     * of the realm implementation if a name has not been assigned.
     */
    public String getName() {
        if( this.name == null ) {
            return getClass().getName();
        } else {
            return this.name;
        }
    }


    /**
     * Checks the returned authorization information for validity.  The default implementation
     * simply checks that it is not null.
     * @param info the info being checked.
     * @param principal the principal that info was retrieved for.
     */
    protected void checkAuthorizationInfo(AuthorizationInfo info, Principal principal) {
        if( info == null ) {
            throw new NoAuthorizationInfoFoundException( "No authorization info found for principal [" + principal + "] in realm [" + getName() + "]" );
        }
    }

    public boolean hasRole(Principal principal, String roleIdentifier) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.hasRole( roleIdentifier );
    }


    public boolean[] hasRoles(Principal principal, List<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.hasRoles( roleIdentifiers );
    }

    public boolean hasAllRoles(Principal principal, Collection<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.hasAllRoles( roleIdentifiers );
    }

    public boolean isPermitted(Principal principal, Permission permission) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.implies( permission );
    }

    public boolean[] isPermitted(Principal principal, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.implies( permissions );
    }

    public boolean isPermittedAll(Principal principal, Collection<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.impliesAll( permissions );
    }

    public void checkPermission(Principal principal, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkPermission( permission );
    }

    public void checkPermissions(Principal principal, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkPermissions( permissions );
    }


}