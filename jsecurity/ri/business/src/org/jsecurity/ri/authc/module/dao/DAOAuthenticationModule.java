/*
 * Copyright (C) 2005 Jeremy C. Haile
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

package org.jsecurity.ri.authc.module.dao;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.ExpiredCredentialException;
import org.jsecurity.authc.IncorrectCredentialException;
import org.jsecurity.authc.LockedAccountException;
import org.jsecurity.authc.UnknownAccountException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.module.AuthenticationModule;
import org.jsecurity.ri.authc.credential.CredentialMatcher;
import org.jsecurity.ri.authc.credential.PlainTextCredentialMatcher;

import java.security.Principal;

/**
 * <p>Module that authenticates a user by delegating the lookup of
 * authentication and authorization information to an {@link AuthenticationDAO}.
 * Users of JSecurity can create their own DAO, or use one of the provided
 * DAO implementations.</p>
 *
 * <p>This module is intended to encapsulate the generic behavior of
 * authenticating a user from a username and password based on the
 * {@link org.jsecurity.authc.AuthenticationInfo} retrieved from the {@link AuthenticationDAO}.</p>
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class DAOAuthenticationModule implements AuthenticationModule {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The DAO used to retrieve user authentication and authorization
     * information from a data store.
     */
    private AuthenticationDAO authenticationDao;

    /**
     * Password matcher used to determine if the provided password matches
     * the password stored in the data store.
     */
    private CredentialMatcher credentialMatcher = new PlainTextCredentialMatcher();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticationDao(AuthenticationDAO authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public void setPasswordMatcher(CredentialMatcher credentialMatcher ) {
        this.credentialMatcher = credentialMatcher;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public boolean supports(Class tokenClass) {
        return UsernamePasswordToken.class.isAssignableFrom( tokenClass );
    }


    public AuthenticationInfo getAuthenticationInfo( AuthenticationToken token )
        throws AuthenticationException {
        Principal accountIdentifier = token.getPrincipal();
        Object submittedCredentials = token.getCredentials();

        AuthenticationInfo info;
        try {
            info = authenticationDao.getAuthenticationInfo( accountIdentifier );
        } catch (Exception e) {
            throw new AuthenticationException(
                "Account [" + accountIdentifier + "] could not be authenticated because an error " +
                "occurred during authentication.", e );
        }

        if( info == null ) {
            String msg = "No account information found for account [" + accountIdentifier + "]";
            throw new UnknownAccountException( msg );
        }

        if( info.isAccountLocked() ) {
            throw new LockedAccountException( "Account [" + accountIdentifier + "] is locked." );
        }

        if( info.isCredentialsExpired() ) {
            String msg = "The credentials for account [" + accountIdentifier + "] are expired";
            throw new ExpiredCredentialException( msg );
        }

        if( !credentialMatcher.doCredentialsMatch( submittedCredentials, info.getCredentials() ) ) {
            String msg = "The credentials provided for account [" +
                         accountIdentifier + "] did not match the expected credentials.";
            throw new IncorrectCredentialException( msg );
        }

        return info;
    }
}