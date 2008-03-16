/*
 * Copyright 2005-2008 Jeremy Haile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
 * @see #queryForLdapAccount (Object, LdapContextFactory)
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

    private LdapContextFactory ldapContextFactory = null;

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

    protected void afterAccountCacheSet() {
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
