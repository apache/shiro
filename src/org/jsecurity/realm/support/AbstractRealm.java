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

package org.jsecurity.realm.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.CredentialMatcher;
import org.jsecurity.authc.credential.support.PlainTextCredentialMatcher;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.NoAuthorizationInfoFoundException;
import org.jsecurity.authz.Permission;
import org.jsecurity.realm.Realm;

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
 * @author Les Hazlewood
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
     * the password stored in the data store.
     */
    protected CredentialMatcher credentialMatcher = new PlainTextCredentialMatcher();

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
    /**
     * Returns the name assigned to this realm instance.  Names must be unique across all realms configured in the
     * system.
     *
     * <p>The default implementation of this method returns the fully-qualified class name of the implementation
     * class.  Therefore, if more than one realm exists of the same type, this method must be called to set a different
     * value.
     *
     * @return the name associated with this realm instance.
     */
    public String getName() {
        if( this.name == null ) {
            return getClass().getName();
        } else {
            return this.name;
        }
    }

    /**
     * Sets the name associated with the realm instance.  Names must be unique across all realms configured in the
     * system.
     *
     * <p>Unless overridden, the realm's default name is the fully qualified name of the implementation class.
     * Therefore, if more than one realm exists of the same type, this method needs to be called to set a different
     * value.
     *
     * @param name the unique name assigned to the realm instance.
     */
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
     * <p>Unless overridden by this method, the default value is a {@link PlainTextCredentialMatcher} instance.
     *
     * @param credentialMatcher the matcher to use.
     */
    public void setCredentialMatcher(CredentialMatcher credentialMatcher) {
        this.credentialMatcher = credentialMatcher;
    }

    /**
     * Returns the authenticationToken class supported by this realm.
     *
     * <p>The default value is <tt>{@link UsernamePasswordToken UsernamePasswordToken.class}</tt>, since
     * about 90% of realms use username/password authentication, regardless of their protocol (e.g. over jdbc, ldap,
     * kerberos, http, etc).
     *
     * <p>Subclasses must override this method if they won't support <tt>UsernamePasswordToken</tt> authentications and
     * they haven't already overridden the {@link #supports} method.
     *
     * @return the authenticationToken class supported by this realm.
     *
     * @see #setAuthenticationTokenClass
     */
    public Class getAuthenticationTokenClass() {
        return authenticationTokenClass;
    }

    /**
     * Sets the authenticationToken class supported by this realm.
     *
     * <p>Unless overridden by this method, the default value is {@link UsernamePasswordToken} to support 90% of
     * application's out of the box.
     *
     * @param authenticationTokenClass the class of authentication token instances supported by this realm.
     *
     * @see #getAuthenticationTokenClass getAuthenticationTokenClass() for more explanation.
     */
    public void setAuthenticationTokenClass(Class<? extends AuthenticationToken> authenticationTokenClass) {
        this.authenticationTokenClass = authenticationTokenClass;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * This method should be implemented by subclasses to retrieve authentication information from a impl-specific
     * datasource (RDBMS, file system, memory, etc) for the given authentication token.
     *
     * <p>A <tt>null</tt> return value means that no account could be associated with
     * the specified token, whereby this class (the {@link #getAuthenticationInfo} method) will then throw an
     * {@link UnknownAccountException} to indicate this condition.
     * 
     * @param token the authentication token containing the user's principal and credentials.
     * @return an {@link AuthenticationInfo} object containing user information resulting from the authentication
     * ONLY if the authentication is successful (i.e. the credentials were correct, etc.)
     * @throws AuthenticationException if there is an error authenticating the user using the given token.
     */    
    protected abstract AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException;


    /**
     * This method should be implemented by subclasses to retrieve authorization information for
     * the given principal.
     * @param principal the principal that authorization information should be retrieved for.
     * @return an {@link AuthorizationInfo} object encapsulating the authorization information
     * associated with the given principal.
     * @throws AuthorizationException if there is an error while retrieving authorization information for
     * the given principal
     * @throws NoAuthorizationInfoFoundException if authorization information could not
     * be found for the given principal.
     */
    protected abstract AuthorizationInfo getAuthorizationInfo(Principal principal) throws AuthorizationException;

    /**
     * Convenience implementation that returns
     * <tt>getAuthenticationTokenClass().isAssignableFrom( tokenClass );</tt>.  Can be overridden
     * by subclasses for more complex token type checking.
     * <p>Most implementations will only need to set a different class via
     * {@link #setAuthenticationTokenClass}, as opposed to overriding this method.
     *
     * @param tokenClass the class of the authenticationToken being submitted for authentication.
     * @return true if this authentication realm "understands" how to process submissions for the submitted token
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

        AuthenticationInfo info = doGetAuthenticationInfo( token );

        if( info == null ) {
            if ( log.isDebugEnabled() ) {
                String msg = "No account information found for submitted authentication token [" + token + "].  " +
                "Returning null to inform calling Authenticator.";
                log.debug( msg );
            }
            return null;
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
            throw new AuthenticationException( "A CredentialMatcher must be configured in order to verify " +
                    "credentials during authentication.  If you do not wish for credentials to be examined, you " +
                    "can configure an AllowAllCredentialMatcher." );
        }

        return info;
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
        return info.isPermitted( permission );
    }

    public boolean[] isPermitted(Principal principal, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.isPermitted( permissions );
    }

    public boolean isPermittedAll(Principal principal, Collection<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        return info.isPermittedAll( permissions );
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


    public void checkRole(Principal principal, String role) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkRole( role );
    }

    public void checkRoles(Principal principal, Collection<String> roles) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkRoles( roles );
    }

    /**
     * Default implementation that always returns false.  Subclasses are expected to override if the default
     * JSecurity mechanisms are not suitable (e.g. JDK 1.5 annotations).
     * 
     * @param action the action to check for authorized execution
     * @return whether or not the realm supports AuthorizedActions of the given type.
     */
    public boolean supports( AuthorizedAction action ) {
        return false;
    }

    public boolean isAuthorized( Principal subjectIdentifier, AuthorizedAction action ) {
        String msg = "Subclasses must override this implementation as such checks are system-specific.";
        throw new UnsupportedOperationException( msg );
    }

    public void checkAuthorization( Principal subjectIdentifier, AuthorizedAction action ) throws AuthorizationException {
        String msg = "Subclasses must override this implementation as such checks are system-specific.";
        throw new UnsupportedOperationException( msg );
    }
}