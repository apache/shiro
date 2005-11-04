/*
 * Copyright (C) 2005 Jeremy C. Haile, Les Hazlewood
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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.module.AuthenticationModule;
import org.jsecurity.ri.authc.AbstractAuthenticator;

import java.util.List;

/**
 * A <tt>PluggableAuthenticator</tt> is an {@link org.jsecurity.authc.Authenticator Authenticator}
 * that delgates authentication duties to a pluggable collection
 * {@link AuthenticationModule AuthenticationModule}s.
 *
 * <p>Using this Authenticator allows you to &quot;plug-in&quot; your own
 * <tt>AuthenticationModule</tt>s as you see fit.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class PluggableAuthenticator extends AbstractAuthenticator {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * List of authentication modules that will be iterated through when a user
     * authenticates.
     */
    private List<AuthenticationModule> modules;



    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setModules(List<AuthenticationModule> modules) {
        this.modules = modules;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * Attempts to authenticate the given token by iterating over the list of
     * {@link AuthenticationModule}s.  For each module, first the {@link AuthenticationModule#supports(Class)}
     * method will be called to determine if the module supports the type of token.  If a module does support
     * the token, its {@link AuthenticationModule#getAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)}
     * method will be called.  If the module returns a non-null authorization context, the token will be
     * considered authenticated and will be returned.  If the module returns a null context, the next
     * module will be consulted.  If no modules support the token or all supported modules return null,
     * an {@link AuthenticationException} will be thrown to indicate that the user could not be authenticated.
     *
     * @param authenticationToken the token containing the authentication principal and credentials for the
     * user being authenticated.
     * @return an authorization context for the authenticated user.
     * @throws AuthenticationException if the user could not be authenticated or the user is denied authentication
     * for the given principal and credentials.
     */
    public AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {

        AuthenticationInfo info = null;

        if (logger.isDebugEnabled()) {
            logger.debug("Iterating through [" + modules.size() + "] authentication modules ");
        }

        for( AuthenticationModule module : modules ) {

            if( module.supports( authenticationToken.getClass() ) ) {

                if (logger.isDebugEnabled()) {
                    logger.debug("Attempting to authenticate token [" + authenticationToken + "] " +
                        "using module of type [" + module.getClass() + "]");
                }

                info = module.getAuthenticationInfo( authenticationToken );

                // If non-null info is returned, then the module was able to authenticate the
                // user - so return the context.
                if( info != null ) {

                    if (logger.isDebugEnabled()) {
                        logger.debug("Account authenticated using module of type [" + module.getClass().getName() + "]");
                    }

                    break;
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Module of type [" + module.getClass().getName() + "] does not support token." );
                }
            }
        }

        // If info is still null, throw an exception - the user was not able to be authenticated
        // by any configured modules.
        if( info == null ) {
            throw new AuthenticationException( "Authentication token of type [" + authenticationToken.getClass() + "] " +
                "could not be authenticated by any configured modules.  Check that the authenticator is configured " +
                "with appropriate modules." );
        } else {
            return info;
        }
    }
}