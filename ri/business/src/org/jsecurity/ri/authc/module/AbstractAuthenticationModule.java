/*
 * Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.ri.authc.module;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.*;
import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authc.module.AuthenticationModule;
import org.jsecurity.ri.authc.credential.CredentialMatcher;

import java.security.Principal;

/**
 * Abstract implementation of the <tt>AuthenticationModule</tt> interface.  Most implementations
 * can subclass this one for protocol-specific behavior.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AbstractAuthenticationModule implements AuthenticationModule {

    protected final transient Log log = LogFactory.getLog( getClass() );

    /**
     * Password matcher used to determine if the provided password matches
     * the password stored in the data store.  Only utilized if non-null.
     */
    protected CredentialMatcher credentialMatcher = null;

    protected Class<? extends AuthenticationToken> authenticationTokenClass = UsernamePasswordToken.class;

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
     * @param credentialMatcher
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
            throw new AuthenticationException(
                "AuthenticationToken [" + token + "] could not be authenticated because an error " +
                "occurred during authentication.", t );
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

    protected abstract AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException;
}
