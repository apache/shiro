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

import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authc.module.AuthenticationModule;
import org.jsecurity.realm.support.ldap.LdapDirectoryInfo;
import org.jsecurity.realm.support.ldap.LdapRealm;
import org.jsecurity.util.NamePrincipal;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * <p>An {@link AuthenticationModule} that authenticates with an active directory LDAP
 * server to determine the roles for a particular user.  This implementation
 * queries for the user's groups and then maps the group names to roles using the
 * {@link #groupRoleMap}.</p>
 *
 * <p>More advanced implementations would likely want to override the
 * {@link #queryForLdapDirectoryInfo(String, javax.naming.ldap.LdapContext)} and
 * {@link #buildAuthenticationInfo(String, char[],org.jsecurity.realm.support.ldap.LdapDirectoryInfo)} methods.</p>
 *
 * @see org.jsecurity.realm.support.ldap.LdapDirectoryInfo
 * @see #queryForLdapDirectoryInfo(String, javax.naming.ldap.LdapContext)
 * @see #buildAuthenticationInfo(String, char[],org.jsecurity.realm.support.ldap.LdapDirectoryInfo)
 *
 * @since 0.1
 * @author Tim Veil
 * @author Jeremy Haile
 */
public class ActiveDirectoryRealm extends LdapRealm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /**
     * Mapping from fully qualified active directory
     * group names (e.g. CN=Group,OU=Company,DC=MyDomain,DC=local)
     * as returned by the active directory LDAP server to role names.
     */
    private Map<String, String> groupRoleMap;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public void setGroupRoleMap(Map<String, String> groupRoleMap) {
        this.groupRoleMap = groupRoleMap;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * <p>Builds an {@link org.jsecurity.realm.support.ldap.LdapDirectoryInfo} object by querying the active directory LDAP context for the
     * specified username.</p>
     *
     * <p>This method can be overridden by subclasses to query the LDAP server in a more complex way.</p>
     *
     * @param username the username whose information should be queried from the LDAP server.
     * @param ctx the LDAP context that is connected to the LDAP server.
     *
     * @return an {@link org.jsecurity.realm.support.ldap.LdapDirectoryInfo} instance containing information retrieved from LDAP
     * that can be used to build an {@link AuthenticationInfo} instance to return.
     *
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected LdapDirectoryInfo queryForLdapDirectoryInfo(String username, LdapContext ctx) throws NamingException {

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
                log.debug( "Adding roles [" + roleNames + "] to LDAP directory info." );
            }

            info.addAllRoleNames( roleNames );

        } else if( attr.getID().equals( "displayName" ) ) {
            Collection<String> names = getAllAttributeValues( attr );
            for( String name : names ) {
                info.addPrincipal( new NamePrincipal( name ) );
            }

        }

    }

    protected Collection<String> translateRoleNames(Collection<String> groupNames) {
        Set<String> roleNames = new HashSet<String>( groupNames.size() );

        if( groupRoleMap != null ) {
            for( String groupName : groupNames ) {
                String roleName = groupRoleMap.get( groupName );
                if( roleName != null ) {

                    if( log.isDebugEnabled() ) {
                        log.debug( "User is member of group [" + groupName + "] so adding role [" + roleName + "]" );
                    }

                    roleNames.add( roleName );
                }
            }
        }
        return roleNames;
    }


}
