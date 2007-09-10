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
package org.jsecurity.realm.support.activedirectory;

import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.support.SimpleAuthorizationInfo;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.support.ldap.AbstractLdapRealm;
import org.jsecurity.realm.support.ldap.LdapContextFactory;
import org.jsecurity.realm.support.ldap.LdapUtils;
import org.jsecurity.util.UsernamePrincipal;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.security.Principal;
import java.util.*;

/**
 * <p>An {@link Realm} that authenticates with an active directory LDAP
 * server to determine the roles for a particular user.  This implementation
 * queries for the user's groups and then maps the group names to roles using the
 * {@link #groupRolesMap}.</p>
 *
 *
 * @since 0.1
 * @author Tim Veil
 * @author Jeremy Haile
 */
public class ActiveDirectoryRealm extends AbstractLdapRealm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    
    private static final String ROLE_NAMES_DELIMETER = ",";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /**
     * Mapping from fully qualified active directory
     * group names (e.g. CN=Group,OU=Company,DC=MyDomain,DC=local)
     * as returned by the active directory LDAP server to role names.
     */
    private Map<String, String> groupRolesMap;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public void setGroupRolesMap(Map<String, String> groupRolesMap) {
        this.groupRolesMap = groupRolesMap;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * <p>Builds an {@link AuthenticationInfo} object by querying the active directory LDAP context for the
     * specified username.  This method binds to the LDAP server using the provided username and password -
     * which if successful, indicates that the password is correct.</p>
     *
     * <p>This method can be overridden by subclasses to query the LDAP server in a more complex way.</p>
     *
     * @param token the authentication token provided by the user.
     * @param ldapContextFactory the factory used to build connections to the LDAP server.
     * @return an {@link AuthenticationInfo} instance containing information retrieved from LDAP
     * that can be used to build an {@link org.jsecurity.authc.AuthenticationInfo} instance to return.
     *
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected AuthenticationInfo queryForLdapAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {

        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        // Binds using the username and password provided by the user.
        ldapContextFactory.getLdapContext( upToken.getUsername(), String.valueOf( upToken.getPassword() ) );

        UsernamePrincipal principal = new UsernamePrincipal( upToken.getUsername() );

        return new SimpleAuthenticationInfo( principal, upToken.getPassword() );
    }


    /**
     * <p>Builds an {@link AuthorizationInfo} object by querying the active directory LDAP context for the
     * groups that a user is a member of.  The groups are then translated to role names by using the
     * configured {@link #groupRolesMap}.</p>
     *
     * <p>Subclasses can override this method to determine authorization information in a more complex way.  Note that
     * this default implementation does not support permissions, only roles.</p>
     *
     * @param principal the principal of the user whose authorization information is being retrieved.
     * @param ldapContextFactory the factory used to create LDAP connections.
     * @return authorization information for the given principal.
     * @throws NamingException if an error occurs when searching the LDAP server.
     */
    protected AuthorizationInfo queryForLdapAuthorizationInfo(Principal principal, LdapContextFactory ldapContextFactory) throws NamingException {

        UsernamePrincipal usernamePrincipal = (UsernamePrincipal) principal;

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String searchFilter = "(&(objectClass=*)(userPrincipalName=" + usernamePrincipal.getUsername() + "))";

        // Perform context search
        LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();
        NamingEnumeration answer = ldapContext.search(searchBase, searchFilter, searchCtls);

        List<String> roleNames = new ArrayList<String>();
        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            log.debug("Retrieving group names for user [" + sr.getName() + "]");

            Attributes attrs = sr.getAttributes();

            if (attrs != null) {
                NamingEnumeration ae = attrs.getAll();
                while( ae.hasMore() ) {
                    Attribute attr = (Attribute) ae.next();

                    if( attr.getID().equals( "memberOf" ) ) {

                        Collection<String> groupNames = LdapUtils.getAllAttributeValues( attr );

                        roleNames.addAll( getRoleNamesForGroups( groupNames ) );
                    }
                }
            }
        }

        return new SimpleAuthorizationInfo( roleNames, null );
    }

    /**
     * This method is called by the default implementation to translate Active Directory group names
     * to role names.  This implementation uses the {@link #groupRolesMap} to map group names to role names.
     * @param groupNames the group names that apply to the current user.
     * @return a collection of roles that are implied by the given role names.
     */
    protected Collection<String> getRoleNamesForGroups(Collection<String> groupNames) {
        Set<String> roleNames = new HashSet<String>( groupNames.size() );

        if( groupRolesMap != null ) {
            for( String groupName : groupNames ) {
                String strRoleNames = groupRolesMap.get( groupName );
                if( strRoleNames != null ) {
                    for( String roleName : strRoleNames.split( ROLE_NAMES_DELIMETER ) ) {

                        if( log.isDebugEnabled() ) {
                            log.debug( "User is member of group [" + groupName + "] so adding role [" + roleName + "]" );
                        }

                        roleNames.add( roleName );

                    }
                }
            }
        }
        return roleNames;
    }


}
