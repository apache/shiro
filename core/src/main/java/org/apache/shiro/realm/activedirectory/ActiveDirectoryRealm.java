/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm.activedirectory;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.ldap.AbstractLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;


/**
 * A {@link Realm} that authenticates with an active directory LDAP
 * server to determine the roles for a particular user.  This implementation
 * queries for the user's groups and then maps the group names to roles using the
 * {@link #groupRolesMap}.
 *
 * @since 0.1
 */
public class ActiveDirectoryRealm extends AbstractLdapRealm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    private static final Logger LOGGER = LoggerFactory.getLogger(ActiveDirectoryRealm.class);

    private static final String ROLE_NAMES_DELIMITER = ",";

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
     * Builds an {@link AuthenticationInfo} object by querying the active directory LDAP context for the
     * specified username.  This method binds to the LDAP server using the provided username and password -
     * which, if successful, indicates that the password is correct.
     * <p/>
     * This method can be overridden by subclasses to query the LDAP server in a more complex way.
     *
     * @param token              the authentication token provided by the user.
     * @param ldapContextFactory the factory used to build connections to the LDAP server.
     * @return an {@link AuthenticationInfo} instance containing information retrieved from LDAP.
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory)
            throws NamingException {

        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        // Binds using the username and password provided by the user.
        LdapContext ctx = null;
        try {
            ctx = ldapContextFactory.getLdapContext(upToken.getUsername(), String.valueOf(upToken.getPassword()));
        } finally {
            LdapUtils.closeContext(ctx);
        }

        return buildAuthenticationInfo(upToken.getUsername(), upToken.getPassword());
    }

    protected AuthenticationInfo buildAuthenticationInfo(String username, char[] password) {
        return new SimpleAuthenticationInfo(username, password, getName());
    }


    /**
     * Builds an {@link org.apache.shiro.authz.AuthorizationInfo} object by querying the active directory LDAP context for the
     * groups that a user is a member of.  The groups are then translated to role names by using the
     * configured {@link #groupRolesMap}.
     * <p/>
     * This implementation expects the <tt>principal</tt> argument to be a String username.
     * <p/>
     * Subclasses can override this method to determine authorization data (roles, permissions, etc.) in a more
     * complex way.  Note that this default implementation does not support permissions, only roles.
     *
     * @param principals         the principal of the Subject whose account is being retrieved.
     * @param ldapContextFactory the factory used to create LDAP connections.
     * @return the AuthorizationInfo for the given Subject principal.
     * @throws NamingException if an error occurs when searching the LDAP server.
     */
    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals,
                                                          LdapContextFactory ldapContextFactory) throws NamingException {

        String username = (String) getAvailablePrincipal(principals);

        // Perform context search
        LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();

        Set<String> roleNames;

        try {
            roleNames = getRoleNamesForUser(username, ldapContext);
        } finally {
            LdapUtils.closeContext(ldapContext);
        }

        return buildAuthorizationInfo(roleNames);
    }

    protected AuthorizationInfo buildAuthorizationInfo(Set<String> roleNames) {
        return new SimpleAuthorizationInfo(roleNames);
    }

    protected Set<String> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
        Set<String> roleNames;
        roleNames = new LinkedHashSet<String>();

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String userPrincipalName = username;
        if (principalSuffix != null
                && !userPrincipalName.toLowerCase(Locale.ROOT).endsWith(principalSuffix.toLowerCase(Locale.ROOT))) {
            userPrincipalName += principalSuffix;
        }

        Object[] searchArguments = new Object[] {userPrincipalName};

        NamingEnumeration answer = ldapContext.search(searchBase, searchFilter, searchArguments, searchControls);

        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Retrieving group names for user [" + sr.getName() + "]");
            }

            Attributes attrs = sr.getAttributes();

            if (attrs != null) {
                NamingEnumeration ae = attrs.getAll();
                while (ae.hasMore()) {
                    Attribute attr = (Attribute) ae.next();

                    if (attr.getID().equals("memberOf")) {

                        Collection<String> groupNames = LdapUtils.getAllAttributeValues(attr);

                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("Groups found for user [" + username + "]: " + groupNames);
                        }

                        Collection<String> rolesForGroups = getRoleNamesForGroups(groupNames);
                        roleNames.addAll(rolesForGroups);
                    }
                }
            }
        }
        return roleNames;
    }

    /**
     * This method is called by the default implementation to translate Active Directory group names
     * to role names.  This implementation uses the {@link #groupRolesMap} to map group names to role names.
     *
     * @param groupNames the group names that apply to the current user.
     * @return a collection of roles that are implied by the given role names.
     */
    protected Collection<String> getRoleNamesForGroups(Collection<String> groupNames) {
        Set<String> roleNames = new HashSet<String>(groupNames.size());

        if (groupRolesMap != null) {
            for (String groupName : groupNames) {
                String strRoleNames = groupRolesMap.get(groupName);
                if (strRoleNames != null) {
                    for (String roleName : strRoleNames.split(ROLE_NAMES_DELIMITER)) {

                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("User is member of group [" + groupName + "] so adding role [" + roleName + "]");
                        }

                        roleNames.add(roleName);

                    }
                }
            }
        }
        return roleNames;
    }

}
