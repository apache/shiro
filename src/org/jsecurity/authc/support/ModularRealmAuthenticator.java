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
 * A <tt>ModularRealmAuthenticator</tt> is an {@link org.jsecurity.authc.Authenticator Authenticator}
 * that delgates authentication duties to a pluggable (modular) collection of
 * {@link Realm}s.  This enables PAM (Pluggable Authentication Module) behavior in JSecurity
 * for authentication.  For all intents and purposes, a JSecurity Realm can be thought of a PAM 'module'.
 *
 * <p>Using this Authenticator allows you to &quot;plug-in&quot; your own
 * <tt>Realm</tt>s as you see fit.  Common realms are those based on accessing
 * LDAP, relational databases, file systems, etc.
 *
 * @see #setRealms
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class ModularRealmAuthenticator extends AbstractAuthenticator {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * List of realms that will be iterated through when a user authenticates.
     */
    private List<? extends Realm> realms;



    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public ModularRealmAuthenticator() {
    }


    public ModularRealmAuthenticator(SecurityManager SecurityManager, List<? extends Realm> realms ) {
        setSecurityManager( SecurityManager );
        this.realms = realms;
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setRealms( List<Realm> realms ) {
        this.realms = realms;
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
     * Merges the <tt>AuthenticationInfo</tt> returned from a single realm into the aggregated
     * <tt>AuthenticationInfo</tt> that summarizes all realms.
     *
     * <p>This method is primarily provided as a template method if subclasses wish to override it for custom
     * merging behavior.
     *
     * <p>The default implementation
     * only checks to see if the <tt>aggregatedInfo</tt> parameter is an <tt>instanceof</tt>
     * {@link SimpleAuthenticationInfo}, and if so, calls
     * <tt>aggregatedInfo.{@link SimpleAuthenticationInfo#merge merge( singleRealmInfo )}</tt>, otherwise
     * nothing occurs.
     *
     * @param aggregatedInfo the aggregated info from all realms
     * @param singleRealmInfo the info provided by a single realm, to be joined with the aggregated info
     */
    protected void merge(AuthenticationInfo aggregatedInfo, AuthenticationInfo singleRealmInfo ) {
        if ( aggregatedInfo instanceof SimpleAuthenticationInfo ) {
            ((SimpleAuthenticationInfo)aggregatedInfo).merge( singleRealmInfo );
        }
    }

    /**
     * Used by the internal {@link #doAuthenticate} implementation to ensure that the <tt>realms</tt> property
     * has been set.  The default implementation ensures the property is not null and not empty.
     * @throws IllegalStateException if the <tt>realms</tt> property is configured incorrectly.
     */
    protected void assertRealmsConfigured() throws IllegalStateException {
        if ( realms == null || realms.size() <= 0 ) {
            String msg = "No realms configured for this ModularRealmAuthenticator.  Configuration error.";
            throw new IllegalStateException( msg );
        }
    }

    /**
     * This is a final 'housekeeping' method that is called after all realms have been consulted during the
     * authentication attempt for the specified token.
     *
     * <p>The default implementation only verifies that one or more realms successfully retrieved AuthenticationInfo
     * for the specified <tt>AuthenticationToken</tt> (i.e. <tt>oneOrMoreSuccessful == true</tt>).  If so, it just
     * returns the <tt>aggregated</tt> argument.  If not, it throws an AuthenticationException stating that no realms
     * could authenticate the token.  Subclasses may override this method for more custom behavior, but a
     * non-null value must be returned (otherwise the authentication attempt is considered to be failed and an
     * exception will be thrown).
     *
     * @param oneOrMoreSuccessful specifies if one or more <tt>Realm</tt>s were able to obtain
     * <tt>AuthenticationInfo</tt> for the specified token
     * @param authenticationToken the token submitted during the login process that encapsulates the user's
     * principals and credentials.
     * @param aggregated the aggregated <tt>AuthenticationInfo</tt> data from all realms that processed the token
     * during the authentication attempt.
     * @return the realms' <tt>AuthenticationInfo</tt> for the given token
     * @throws AuthenticationException if no realms could associate any <tt>AuthenticationInfo</tt> with the token
     */
    protected AuthenticationInfo realmsComplete( boolean oneOrMoreSuccessful, AuthenticationToken authenticationToken,
                                                  AuthenticationInfo aggregated ) throws AuthenticationException {
        // If no realm authenticated the user, throw an exception
        if( !oneOrMoreSuccessful ) {
            throw new AuthenticationException( "Authentication token of type [" + authenticationToken.getClass() + "] " +
                "could not be authenticated by any configured realms.  Check that this authenticator is configured " +
                "with appropriate realms." );
        } else {
            return aggregated;
        }
    }


    /**
     * <p>Attempts to authenticate the given token by iterating over the internal collection of
     * {@link Realm}s.  For each realm, first the {@link Realm#supports(Class)}
     * method will be called to determine if the realm supports the <tt>authenticationToken</tt> method argument.
     *
     * If a realm does support
     * the token, its {@link Realm#getAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)}
     * method will be called.  If the realm returns non-null authentication information, the token will be
     * considered authenticated and the authentication info recorded.  If the realm returns <tt>null</tt>, the next
     * realm will be consulted.  If no realms support the token or all supported realms return null,
     * an {@link AuthenticationException} will be thrown to indicate that the user could not be authenticated.
     *
     * <p>After all realms have been consulted, the information from each realm is aggregated into a single
     * {@link AuthenticationInfo} object and returned.
     *
     * @param authenticationToken the token containing the authentication principal and credentials for the
     * user being authenticated.
     * @return an authorization context for the authenticated user.
     * @throws AuthenticationException if the user could not be authenticated or the user is denied authentication
     * for the given principal and credentials.
     */
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {

        assertRealmsConfigured();

        AuthenticationInfo aggregatedInfo = createAggregatedAuthenticationInfo( authenticationToken );

        if (logger.isDebugEnabled()) {
            logger.debug("Iterating through [" + realms.size() + "] realms");
        }

        boolean authenticated = false;
        for( Realm realm : realms) {

            if( realm.supports( authenticationToken.getClass() ) ) {

                if (logger.isDebugEnabled()) {
                    logger.debug("Attempting to authenticate token [" + authenticationToken + "] " +
                        "using realm of type [" + realm.getClass() + "]");
                }

                AuthenticationInfo realmInfo = realm.getAuthenticationInfo( authenticationToken );

                // If non-null info is returned, then the realm was able to authenticate the
                // user - so return the context.
                if( realmInfo != null ) {

                    if (logger.isDebugEnabled()) {
                        logger.debug("Account authenticated using realm of type [" + realm.getClass().getName() + "]");
                    }

                    // Merge the module-returned data with the aggregate data
                    merge( aggregatedInfo, realmInfo );
                    authenticated = true;

                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Realm of type [" + realm.getClass().getName() + "] does not support token " +
                            "of type [" + authenticationToken.getClass().getName() + "].  Skipping realm." );
                }
            }
        }

        AuthenticationInfo info = realmsComplete( authenticated, authenticationToken, aggregatedInfo );
        if ( info == null ) {
            throw new AuthenticationException( "Authentication token of type [" + authenticationToken.getClass() + "] " +
                "could not be authenticated by any configured realms.  Check that this authenticator is configured " +
                "with appropriate realms." );
        }

        return info;
    }
}