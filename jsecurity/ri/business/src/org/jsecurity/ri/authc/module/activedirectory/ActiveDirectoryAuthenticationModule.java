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
package org.jsecurity.ri.authc.module.activedirectory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authc.module.AuthenticationModule;
import org.jsecurity.ri.authc.module.dao.SimpleAuthenticationInfo;
import org.jsecurity.ri.util.UsernamePrincipal;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

/**
 * <p>An {@link AuthenticationModule} that authenticates with an active directory LDAP
 * server to determine the roles for a particular user.  This module accepts authentication
 * tokens of type {@link UsernamePasswordToken}.  This implementation only returns roles for a
 * particular user, and not permissions - but it can be subclassed to build a permission
 * list as well.</p>
 *
 * <p>More advanced implementations would likely want to override the
 * {@link #getActiveDirectoryInfo(String, javax.naming.ldap.LdapContext)} and
 * {@link #buildAuthenticationInfo(String, char[], ActiveDirectoryInfo)} methods.</p>
 *
 * @see ActiveDirectoryInfo
 * @see #getActiveDirectoryInfo(String, javax.naming.ldap.LdapContext)
 * @see #buildAuthenticationInfo(String, char[], ActiveDirectoryInfo) 
 *
 * @author Tim Veil
 * @author Jeremy Haile
 */
public class ActiveDirectoryAuthenticationModule implements AuthenticationModule {

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
     * The type of LDAP authentication to perform.
     */
    private String authentication = "simple";

    /**
     * A suffix appended to the username when searching in the LDAP context.
     * This is typically for domain names.  (e.g. "@MyDomain.local")
     */
    private String principalSuffix = null;

    /**
     * The search base for the search to perform in the LDAP server.
     * (e.g. OU=OrganizationName,DC=MyDomain,DC=local )
     */
    private String searchBase = null;

    /**
     * The context factory to use. This defaults to the SUN LDAP JNDI implementation
     * but can be overridden to use custom LDAP factories.
     */
    private String contextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

    /**
     * The LDAP url to connect to. (e.g. ldap://<activeDirectoryHostname>:<port>)
     */
    private String url = null;

    /**
     * The LDAP referral property.  Defaults to "follow"
     */
    private String refferal = "follow";

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public void setPrincipalSuffix(String principalSuffix) {
        this.principalSuffix = principalSuffix;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    public void setContextFactory(String contextFactory) {
        this.contextFactory = contextFactory;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setRefferal(String refferal) {
        this.refferal = refferal;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public boolean supports(Class tokenClass) {
        return UsernamePasswordToken.class.isAssignableFrom( tokenClass );
    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        ActiveDirectoryInfo activeDirectoryInfo = performAuthentication(upToken.getUsername(), upToken.getPassword());

        return buildAuthenticationInfo( upToken.getUsername(), upToken.getPassword(), activeDirectoryInfo );
    }

    /**
     * Builds an {@link AuthenticationInfo} object to return based on an {@link ActiveDirectoryInfo} object
     * returned from {@link #performAuthentication(String, char[])}
     *
     * @param username the username of the user being authenticated.
     * @param password the password of the user being authenticated.
     * @param activeDirectoryInfo the active directory information queried from the active directory
     * LDAP server.
     * @return an instance of {@link AuthenticationInfo} that represents the principal, credentials, and
     * roles that this user has.
     */
    protected AuthenticationInfo buildAuthenticationInfo(String username, char[] password, ActiveDirectoryInfo activeDirectoryInfo) {
        UsernamePrincipal principal = new UsernamePrincipal( username );

        return new SimpleAuthenticationInfo( principal, password, activeDirectoryInfo.getRoleNames() );
    }


    /**
     * Performs the actual authentication of the user by connecting to the LDAP server, querying it
     * for user information, and returning an {@link ActiveDirectoryInfo} instance containing the
     * results.
     *
     * <p>Typically, users that need special behavior will not override this method, but will instead
     * override {@link #getActiveDirectoryInfo(String, javax.naming.ldap.LdapContext)}</p>
     *
     * @param username the username of the user being authenticated.
     * @param password the password of the user being authenticated.
     *
     * @return the results of the active directory search.
     */
    protected ActiveDirectoryInfo performAuthentication(String username, char[] password) {

        if( searchBase == null ) {
            throw new IllegalStateException( "A search base must be specified." );
        }
        if( url == null ) {
            throw new IllegalStateException( "An LDAP URL must be specified of the form ldap://<hostname>:<port>" );
        }


        if( principalSuffix != null ) {
            username = username + principalSuffix;
        }

        Hashtable<String, String> env = new Hashtable<String, String>(6);

        env.put(Context.SECURITY_AUTHENTICATION, authentication);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, new String( password ));
        env.put(Context.INITIAL_CONTEXT_FACTORY, contextFactory);
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.REFERRAL, refferal);

        if (log.isDebugEnabled()) {
            log.debug( "Initializing LDAP context using environment properties [" + env + "]" );
        }

        LdapContext ctx = null;
        try {
            ctx = new InitialLdapContext(env, null);

            return getActiveDirectoryInfo(username, ctx);


        } catch (NamingException e) {
            throw new AuthenticationException( "LDAP naming error while attempting to authenticate user.", e );

        } finally {
            // Always close the LDAP context
            try {
                if (ctx != null) {
                    ctx.close();
                }
            } catch (NamingException e) {
                if( log.isErrorEnabled() ) {
                    log.error("Problem closing Context: ", e);
                }
            }
        }
    }

    /**
     * Builds an active directory info object by querying the given LDAP context for the
     * specified username.  The default implementation queries for all groups that
     * the user is a member of and returns them as roles for that user.
     *
     * <p>This method can be overridden by subclasses to query the LDAP server
     *
     * @param username the username whose information should be queried from the Active Directory
     * LDAP server.
     * @param ctx the LDAP context that is connected to the active directory server.
     *
     * @return an {@link ActiveDirectoryInfo} instance containing information retrieved from LDAP
     * that can be used to build an {@link AuthenticationInfo} instance to return.
     *
     * @throws NamingException if any LDAP errors occur during the search.
     */
    private ActiveDirectoryInfo getActiveDirectoryInfo(String username, LdapContext ctx) throws NamingException {

        Set<String> groupNames = new HashSet<String>();
        Set<String> emailAddresses = new HashSet<String>();

        String[] returnedAtts = {"memberOf"};

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setReturningAttributes(returnedAtts);

        String searchFilter = "(&(objectClass=*)(userPrincipalName=" + username + "))";

        // Perform context search
        NamingEnumeration answer = ctx.search(searchBase, searchFilter, searchCtls);

        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            log.debug("Retrieving group names for user [" + sr.getName() + "]");

            Attributes attrs = sr.getAttributes();

            if (attrs != null) {
                NamingEnumeration ae = attrs.getAll();
                while( ae.hasMore() ) {
                    Attribute attr = (Attribute) ae.next();

                    if( attr.getID().equals( "memberOf" ) ) {
                        groupNames.addAll( getAllAttributeValues(attr) );
                    } else {
                        throw new RuntimeException( "Unexpected attribute type [" + attr.getID() + "] found in search results." );
                    }
                }
            }
        }

        if( log.isDebugEnabled() ) {
            log.debug( "Returning active directory info with roles [" + groupNames + "] and e-mails [" + emailAddresses + "]" );
        }

        ActiveDirectoryInfo info = new ActiveDirectoryInfo();
        info.setRoleNames( groupNames );

        return info;
    }


    /**
     * Helper method used to retrieve all attribute values from a particular context attribute.
     */
    private Collection<String> getAllAttributeValues(Attribute attr) throws NamingException {
        Set<String> values = new HashSet<String>();
        for (NamingEnumeration e = attr.getAll(); e.hasMore();) {
            String value = (String) e.next();
            values.add( value );
        }
        return values;
    }

}
