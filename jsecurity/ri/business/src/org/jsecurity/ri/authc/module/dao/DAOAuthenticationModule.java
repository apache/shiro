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

import org.jsecurity.authc.*;
import org.jsecurity.authc.module.AuthenticationModule;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.authc.password.PasswordMatcher;
import org.jsecurity.ri.authc.password.PlainTextPasswordMatcher;
import org.jsecurity.ri.authz.SimpleAuthorizationContext;
import org.jsecurity.ri.authz.UsernamePrincipal;

import java.io.Serializable;
import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>Module that authenticates a user by delegating the lookup of
 * authentication and authorization information to an {@link AuthenticationDAO}.
 * Users of JSecurity can create their own DAO, or use one of the provided
 * DAO implementations.</p>
 *
 * <p>This module is intended to encapsulate the generic behavior of
 * authenticating a user from a username and password based on the
 * {@link AuthenticationInfo} retrieved from the {@link AuthenticationDAO}.</p>
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
    private PasswordMatcher passwordMatcher = new PlainTextPasswordMatcher();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthenticationDao(AuthenticationDAO authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public void setPasswordMatcher(PasswordMatcher passwordMatcher) {
        this.passwordMatcher = passwordMatcher;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public boolean supports(Class tokenClass) {
        return UsernamePasswordToken.class.isAssignableFrom( tokenClass );
    }


    public AuthorizationContext authenticate(AuthenticationToken token) throws AuthenticationException {

        String username = getUsername( token );
        char[] password = getPassword( token );

        AuthenticationInfo info = null;
        try {
            info = authenticationDao.getUserAuthenticationInfo( username );
        } catch (Exception e) {
            throw new AuthenticationException(
                "User [" + username + "] could not be authenticated because an error occurred " +
                "during authentication.", e );
        }

        if( info == null ) {
            throw new UnknownAccountException( "No account information found for username [" + username + "]" );
        }

        if( info.isAccountLocked() ) {
            throw new LockedAccountException( "The account for user [" + username + "] is locked." );
        }

        if( info.isCredentialsExpired() ) {
            throw new ExpiredCredentialException( "The credentials for user [" + username + "] are expired." );
        }

        if( !passwordMatcher.doPasswordsMatch( password, info.getPassword() ) ) {
            throw new IncorrectCredentialException( "The password provided for user [" + username + "] was incorrect." );
        }

        return buildAuthorizationContext( info );
    }


    private AuthorizationContext buildAuthorizationContext(AuthenticationInfo info) {

        Principal principal = new UsernamePrincipal( info.getUsername() );

        SimpleAuthorizationContext authContext = new SimpleAuthorizationContext( principal,
                                                                                 info.getRoles(),
                                                                                 info.getPermissions());

        return authContext;
    }


    private Set<Permission> getPermissionsForRoles(Collection<? extends Serializable> roles) {
        return new HashSet<Permission>();
    }


    protected String getUsername(AuthenticationToken token) {
        return ((UsernamePasswordToken)token).getUsername();
    }

    private char[] getPassword(AuthenticationToken token) {
        return ((UsernamePasswordToken)token).getPassword();
    }



}