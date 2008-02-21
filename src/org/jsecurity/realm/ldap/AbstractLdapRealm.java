/*
 * Copyright (C) 2005 Jeremy Haile
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
package org.jsecurity.realm.ldap;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.Initializable;

import javax.naming.NamingException;

/**
 * <p>A {@link Realm} that authenticates with an LDAP
 * server to build the Subject for a user.  This implementation only returns roles for a
 * particular user, and not permissions - but it can be subclassed to build a permission
 * list as well.</p>
 *
 * <p>Implementations would need to implement the
 * {@link #queryForLdapAccount(org.jsecurity.authc.AuthenticationToken,LdapContextFactory) queryForLdapAccount} and
 * {@link #queryForLdapAccount(Object,LdapContextFactory) queryForLdapAccount} abstract methods.</p>
 *
 * <p>By default, this implementation will create an instance of {@link DefaultLdapContextFactory} to use for
 * creating LDAP connections using the principalSuffix, searchBase, url, systemUsername, and systemPassword properties
 * specified on the realm.  The remaining settings use the defaults of {@link DefaultLdapContextFactory}, which are usually
 * sufficient.  If more customized connections are needed, you should inject a custom {@link LdapContextFactory}, which
 * will cause these properties specified on the realm to be ignored.</p>
 *
 * @author Jeremy Haile
 * @see #queryForLdapAccount (org.jsecurity.authc.AuthenticationToken, LdapContextFactory)
 * @see # queryForLdapAccount (Object, LdapContextFactory)
 * @since 0.1
 */
public abstract class AbstractLdapRealm extends AuthorizingRealm implements Initializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/


    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected String principalSuffix = null;

    protected String searchBase = null;

    protected String url = null;

    protected String systemUsername = null;

    protected String systemPassword = null;

    private LdapContextFactory ldapContextFactory;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param principalSuffix the suffix.
     * @see DefaultLdapContextFactory#setPrincipalSuffix(String)
     */
    public void setPrincipalSuffix( String principalSuffix ) {
        this.principalSuffix = principalSuffix;
    }

    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param searchBase the search base.
     * @see DefaultLdapContextFactory#setSearchBase(String)
     */
    public void setSearchBase( String searchBase ) {
        this.searchBase = searchBase;
    }

    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param url the LDAP url.
     * @see DefaultLdapContextFactory#setUrl(String)
     */
    public void setUrl( String url ) {
        this.url = url;
    }

    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param systemUsername the username to use when logging into the LDAP server for authorization.
     * @see DefaultLdapContextFactory#setSystemUsername(String)
     */
    public void setSystemUsername( String systemUsername ) {
        this.systemUsername = systemUsername;
    }


    /**
     * Used when initializing the default {@link LdapContextFactory}.  This property is ignored if a custom
     * <tt>LdapContextFactory</tt> is specified.
     *
     * @param systemPassword the password to use when logging into the LDAP server for authorization.
     * @see DefaultLdapContextFactory#setSystemPassword(String)
     */
    public void setSystemPassword( String systemPassword ) {
        this.systemPassword = systemPassword;
    }


    /**
     * Configures the {@link LdapContextFactory} implementation that is used to create LDAP connections for
     * authentication and authorization.  If this is set, the {@link LdapContextFactory} provided will be used.
     * Otherwise, a {@link DefaultLdapContextFactory} instance will be created based on the properties specified
     * in this realm.
     * @param ldapContextFactory the factory to use - if not specified, a default factory will be created automatically.
     */
    public void setLdapContextFactory(LdapContextFactory ldapContextFactory) {
        this.ldapContextFactory = ldapContextFactory;
    }


    /*--------------------------------------------
    |               M E T H O D S                |
    ============================================*/

    protected void onInit() {
        if( ldapContextFactory == null ) {

            if( log.isDebugEnabled() ) {
                log.debug( "No LdapContextFactory is specified, so a default instance is being created." );
            }

            DefaultLdapContextFactory defaultFactory = new DefaultLdapContextFactory();
            defaultFactory.setPrincipalSuffix( this.principalSuffix );
            defaultFactory.setSearchBase( this.searchBase );
            defaultFactory.setUrl( this.url );
            defaultFactory.setSystemUsername( this.systemUsername );
            defaultFactory.setSystemPassword( this.systemPassword );

            ldapContextFactory = defaultFactory;
        }
    }


    protected Account doGetAccount( AuthenticationToken token ) throws AuthenticationException {
        Account account = null;
        try {
            account = queryForLdapAccount( token, this.ldapContextFactory );
        } catch ( NamingException e ) {
            final String message = "LDAP naming error while attempting to authenticate user.";
            if ( log.isErrorEnabled() ) {
                log.error( message, e );
            }
        }

        return account;
    }




    protected AuthorizingAccount doGetAccount( Object principal ) {
        AuthorizingAccount authorizingAccount = null;
        try {
            authorizingAccount = queryForLdapAccount( principal, this.ldapContextFactory );
        } catch( NamingException e ) {
            final String message = "LDAP naming error while attempting to retrieve authorization for user [" + principal + "].";
            if ( log.isErrorEnabled() ) {
                log.error( message, e );
            }
        }

        return authorizingAccount;
    }


    /**
     * <p>Abstract method that should be implemented by subclasses to builds an
     * {@link org.jsecurity.authc.Account} object by querying the LDAP context for the
     * specified username.</p>
     *
     * @param token the authentication token given during authentication.
     * @param ldapContextFactory factory used to retrieve LDAP connections.
     * @return an {@link org.jsecurity.authz.SimpleAuthorizingAccount} instance containing information retrieved from the LDAP server.
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected abstract Account queryForLdapAccount( AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException;


    /**
     * <p>Abstract method that should be implemented by subclasses to builds an
     * {@link org.jsecurity.authz.SimpleAuthorizingAccount} object by querying the LDAP context for the
     * specified principal.</p>
     *
     * @param principal the principal of the Subject whose Account should be queried from the LDAP server.
     * @param ldapContextFactory factory used to retrieve LDAP connections.
     * @return an {@link org.jsecurity.authz.SimpleAuthorizingAccount} instance containing information retrieved from the LDAP server.
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected abstract AuthorizingAccount queryForLdapAccount( Object principal, LdapContextFactory ldapContextFactory) throws NamingException;

}
