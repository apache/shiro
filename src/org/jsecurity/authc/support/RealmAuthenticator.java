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

package org.jsecurity.authc.support;

import org.jsecurity.SecurityManager;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.Realm;

import java.util.List;

/**
 * A <tt>ModularAuthenticator</tt> is an {@link org.jsecurity.authc.Authenticator Authenticator}
 * that delgates authentication duties to a pluggable collection
 * {@link Realm Realm}s.  This in essense enables
 * PAM (Pluggable Authentication Module) behavior in JSecurity.
 *
 * <p>Using this Authenticator allows you to &quot;plug-in&quot; your own
 * <tt>Realm</tt>s as you see fit.  Common modules are those based on accessing
 * LDAP, relational databases, file systems, etc.
 *
 * @see #setModules
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class RealmAuthenticator extends AbstractAuthenticator {

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
    private List<? extends Realm> modules;



    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public RealmAuthenticator() {
    }


    public RealmAuthenticator(SecurityManager SecurityManager, List<? extends Realm> modules) {
        setSecurityManager( SecurityManager );
        this.modules = modules;
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setModules(List<Realm> modules) {
        this.modules = modules;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Provided for subclass overriding behavior if necessary.
     * 
     * <p>Default implementation only returns <tt>new SimpleAuthenticationInfo();</tt>.
     *
     * <p>If this method is overridden to _not_ return an instance of <tt>SimpleAuthenticationInfo</tt>,
     * then the {@link #merge} method will need to be overridden as well.  Please see that method's JavaDoc
     * for more info.
     *
     * @param token the authentication token submitted during the authentication process which may be useful
     * to subclasses in constructing the returned <tt>AuthenticationInfo</tt> instance.
     * @return an <tt>AuthenticationInfo</tt> instance that will be used to aggregate all
     * <tt>AuthenticationInfo</tt> objects returned by all configured <tt>Realm</tt>s.
     */
    protected AuthenticationInfo createAggregatedAuthenticationInfo( AuthenticationToken token ) {
        return new SimpleAuthenticationInfo();
    }

    /**
     * Merges the <tt>AuthenticationInfo</tt> returned from a module into the aggregated
     * <tt>AuthenticationInfo</tt> that summarizes all modules.
     *
     * <p>This method is primarily provided as a template method if subclasses wish to override it for custom
     * merging behavior.
     *
     * <p>The default implementation
     * only checks to see if the <tt>aggregatedInfo</tt> parameter is an <tt>instanceof</tt>
     * {@link SimpleAuthenticationInfo}, and if so, calls
     * <tt>aggregatedInfo.{@link SimpleAuthenticationInfo#merge merge( moduleInfo )}</tt>, otherwise
     * nothing occurs.
     *
     * @param aggregatedInfo the aggregated info from all authentication modules
     * @param moduleInfo the info provided by a single authentication module, to be joined with the aggregated info
     */
    protected void merge(AuthenticationInfo aggregatedInfo, AuthenticationInfo moduleInfo) {
        if ( aggregatedInfo instanceof SimpleAuthenticationInfo ) {
            ((SimpleAuthenticationInfo)aggregatedInfo).merge( moduleInfo );
        }
    }

    /**
     * Used by the internal {@link #doAuthenticate} implementation to ensure that the <tt>modules</tt> property
     * has been set.  The default implementation ensures the property is not null and not empty.
     * @throws IllegalStateException if the <tt>modules</tt> property is configured incorrectly.
     */
    protected void assertModulesConfigured() throws IllegalStateException {
        if ( modules == null || modules.size() <= 0 ) {
            String msg = "No authentication modules configured for this ModularAuthenticator.  Configuration error.";
            throw new IllegalStateException( msg );
        }
    }

    /**
     * This is a final 'housekeeping' method that is called after all modules have been consulted during the
     * authentication attempt for the specified token.
     *
     * <p>The default implementation only verifies that one or more modules successfully retrieved AuthenticationInfo
     * for the specified <tt>AuthenticationToken</tt> (i.e. <tt>oneOrMoreSuccessful == true</tt>).  If so, it just
     * returns the <tt>aggregated</tt> argument.  If not, it throws an AuthenticationException stating that no modules
     * could authenticate the token.  Subclasses may override this method for more custom behavior, but a
     * non-null value must be returned (otherwise the authentication attempt is considered to be failed and an
     * exception will be thrown).
     *
     * @param oneOrMoreSuccessful specifies if one or more <tt>Realm</tt>s were able to obtain
     * <tt>AuthenticationInfo</tt> for the specified token
     * @param authenticationToken the token submitted during the login process that encapsulates the user's
     * principals and credentials.
     * @param aggregated the aggregated <tt>AuthenticationInfo</tt> data from all modules that processed the token
     * during the authentication attempt.
     * @return the modules' <tt>AuthenticationInfo</tt> for the given token
     * @throws AuthenticationException if no modules could associate any <tt>AuthenticationInfo</tt> with the token
     */
    protected AuthenticationInfo modulesComplete( boolean oneOrMoreSuccessful, AuthenticationToken authenticationToken,
                                                  AuthenticationInfo aggregated ) throws AuthenticationException {
        // If no module authenticated the user, throw an exception
        if( !oneOrMoreSuccessful ) {
            throw new AuthenticationException( "Authentication token of type [" + authenticationToken.getClass() + "] " +
                "could not be authenticated by any configured modules.  Check that this authenticator is configured " +
                "with appropriate modules." );
        } else {
            return aggregated;
        }
    }


    /**
     * <p>Attempts to authenticate the given token by iterating over the internal collection of
     * {@link Realm}s.  For each module, first the {@link Realm#supports(Class)}
     * method will be called to determine if the module supports the <tt>authenticationToken</tt> method argument.
     *
     * If a module does support
     * the token, its {@link Realm#getAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)}
     * method will be called.  If the module returns non-null authentication information, the token will be
     * considered authenticated and the authentication info recorded.  If the module returns <tt>null</tt>, the next
     * module will be consulted.  If no modules support the token or all supported modules return null,
     * an {@link AuthenticationException} will be thrown to indicate that the user could not be authenticated.
     *
     * <p>After all modules have been consulted, the information from each module is aggregated into a single
     * {@link AuthenticationInfo} object and returned.
     *
     * @param authenticationToken the token containing the authentication principal and credentials for the
     * user being authenticated.
     * @return an authorization context for the authenticated user.
     * @throws AuthenticationException if the user could not be authenticated or the user is denied authentication
     * for the given principal and credentials.
     */
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {

        assertModulesConfigured();

        AuthenticationInfo aggregatedInfo = createAggregatedAuthenticationInfo( authenticationToken );

        if (logger.isDebugEnabled()) {
            logger.debug("Iterating through [" + modules.size() + "] authentication modules ");
        }

        boolean authenticated = false;
        for( Realm module : modules ) {

            if( module.supports( authenticationToken.getClass() ) ) {

                if (logger.isDebugEnabled()) {
                    logger.debug("Attempting to authenticate token [" + authenticationToken + "] " +
                        "using module of type [" + module.getClass() + "]");
                }

                AuthenticationInfo moduleInfo = module.getAuthenticationInfo( authenticationToken );

                // If non-null info is returned, then the module was able to authenticate the
                // user - so return the context.
                if( moduleInfo != null ) {

                    if (logger.isDebugEnabled()) {
                        logger.debug("Account authenticated using module of type [" + module.getClass().getName() + "]");
                    }

                    // Merge the module-returned data with the aggregate data
                    merge( aggregatedInfo, moduleInfo );
                    authenticated = true;

                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Module of type [" + module.getClass().getName() + "] does not support token " +
                            "of type [" + authenticationToken.getClass().getName() + "].  Skipping module." );
                }
            }
        }

        AuthenticationInfo info = modulesComplete( authenticated, authenticationToken, aggregatedInfo );
        if ( info == null ) {
            throw new AuthenticationException( "Authentication token of type [" + authenticationToken.getClass() + "] " +
                "could not be authenticated by any configured modules.  Check that this authenticator is configured " +
                "with appropriate modules." );
        }

        return info;
    }
}