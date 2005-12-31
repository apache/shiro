/*
 * Copyright (C) 2005 Tim Veil, Jeremy Haile
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
import org.jsecurity.authc.IncorrectCredentialException;
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
import java.security.Principal;
import java.util.*;

/**
 * <p>An {@link AuthenticationModule} that authenticates with an active directory LDAP
 * server to determine the roles for a particular user.  This module accepts authentication
 * tokens of type {@link UsernamePasswordToken}.  This implementation only returns roles for a
 * particular user, and not permissions - but it can be subclassed to build a permission
 * list as well.</p>
 *
 * <p>More advanced implementations would likely want to override the
 * {@link #getLdapDirectoryInfo(String, javax.naming.ldap.LdapContext)} and
 * {@link #buildAuthenticationInfo(String, char[], LdapDirectoryInfo)} methods.</p>
 *
 * todo This class needs to be refactored to have an LdapAuthenticationModule superclass
 *
 * @see LdapDirectoryInfo
 * @see #getLdapDirectoryInfo(String, javax.naming.ldap.LdapContext)
 * @see #buildAuthenticationInfo(String, char[], LdapDirectoryInfo)
 *
 * @since 0.1
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

    /**
     * Mapping from fully qualified group names (e.g. CN=Group,OU=Company,DC=MyDomain,DC=local)
     * as returned by active directory to role names.
     */
    private Map<String, String> groupRoleMap;

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

    public void setGroupRoleMap(Map<String, String> groupRoleMap) {
        this.groupRoleMap = groupRoleMap;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public boolean supports(Class tokenClass) {
        return UsernamePasswordToken.class.isAssignableFrom( tokenClass );
    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        LdapDirectoryInfo ldapDirectoryInfo = performAuthentication(upToken.getUsername(), upToken.getPassword());

        return buildAuthenticationInfo( upToken.getUsername(), upToken.getPassword(), ldapDirectoryInfo );
    }

    /**
     * Builds an {@link AuthenticationInfo} object to return based on an {@link LdapDirectoryInfo} object
     * returned from {@link #performAuthentication(String, char[])}
     *
     * @param username the username of the user being authenticated.
     * @param password the password of the user being authenticated.
     * @param ldapDirectoryInfo the LDAP directory information queried from the LDAP server.
     * @return an instance of {@link AuthenticationInfo} that represents the principal, credentials, and
     * roles that this user has.
     */
    protected AuthenticationInfo buildAuthenticationInfo(String username, char[] password, LdapDirectoryInfo ldapDirectoryInfo) {
        List<Principal> principals = new ArrayList<Principal>( ldapDirectoryInfo.getPrincipals().size() + 1 );

        UsernamePrincipal principal = new UsernamePrincipal( username );

        principals.add( principal );
        principals.addAll( ldapDirectoryInfo.getPrincipals() );

        return new SimpleAuthenticationInfo( principals, password, ldapDirectoryInfo.getRoleNames() );
    }


    /**
     * Performs the actual authentication of the user by connecting to the LDAP server, querying it
     * for user information, and returning an {@link LdapDirectoryInfo} instance containing the
     * results.
     *
     * <p>Typically, users that need special behavior will not override this method, but will instead
     * override {@link #getLdapDirectoryInfo(String, javax.naming.ldap.LdapContext)}</p>
     *
     * @param username the username of the user being authenticated.
     * @param password the password of the user being authenticated.
     *
     * @return the results of the LDAP directory search.
     */
    protected LdapDirectoryInfo performAuthentication(String username, char[] password) {

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
            log.debug( "Initializing LDAP context using URL [" + url + "] for user [" + username + "]." );
        }

        LdapContext ctx = null;
        try {
            ctx = new InitialLdapContext(env, null);

            return getLdapDirectoryInfo(username, ctx);


        } catch (javax.naming.AuthenticationException e) {
            throw new IncorrectCredentialException( "User could not be authenticated with LDAP server.", e );

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
     * Builds an {@link LdapDirectoryInfo} object by querying the given LDAP context for the
     * specified username.  The default implementation queries for all groups that
     * the user is a member of and returns them as roles for that user.
     *
     * <p>This method can be overridden by subclasses to query the LDAP server
     *
     * @param username the username whose information should be queried from the LDAP server.
     * @param ctx the LDAP context that is connected to the LDAP server.
     *
     * @return an {@link LdapDirectoryInfo} instance containing information retrieved from LDAP
     * that can be used to build an {@link AuthenticationInfo} instance to return.
     *
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected LdapDirectoryInfo getLdapDirectoryInfo(String username, LdapContext ctx) throws NamingException {

        LdapDirectoryInfo info = new LdapDirectoryInfo();


        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

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
                    processAttribute(info, attr);
                }
            }
        }

        return info;
    }

    protected void processAttribute(LdapDirectoryInfo info, Attribute attr) throws NamingException {

        if( attr.getID().equals( "memberOf" ) ) {

            Collection<String> groupNames = getAllAttributeValues(attr);
            Collection<String> roleNames = translateRoleNames(groupNames);

            if( log.isDebugEnabled() ) {
                log.debug( "Adding roles [" + groupNames + "] to LDAP directory info." );
            }

            info.addAllRoleNames( roleNames );

        }

    }

    protected Collection<String> translateRoleNames(Collection<String> groupNames) {
        Set<String> roleNames = new HashSet<String>( groupNames.size() );

        for( String groupName : groupNames ) {
            String roleName = groupRoleMap.get( groupName );
            roleNames.add( roleName );
        }
        return roleNames;
    }


    /**
     * Helper method used to retrieve all attribute values from a particular context attribute.
     */
    protected Collection<String> getAllAttributeValues(Attribute attr) throws NamingException {
        Set<String> values = new HashSet<String>();
        for (NamingEnumeration e = attr.getAll(); e.hasMore();) {
            String value = (String) e.next();
            values.add( value );
        }
        return values;
    }

    public static void main(String[] args) {
        ActiveDirectoryAuthenticationModule m = new ActiveDirectoryAuthenticationModule();
        m.setUrl( "ldap://10.0.0.2:389" );
        m.setSearchBase( "OU=SolTech,DC=Solad,DC=local" );
        m.setPrincipalSuffix( "@Solad.local" );

        UsernamePasswordToken t = new UsernamePasswordToken( "jhaile", "differen" );
        AuthenticationInfo ai = m.getAuthenticationInfo( t );
        System.out.println( ai );
        for( String roleName : ai.getRoles() ) {
            System.out.println( roleName );
        }
    }
}
