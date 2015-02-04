/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.security.shiro;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.apache.isis.security.shiro.permrolemapper.PermissionToRoleMapperFromString;
import org.apache.isis.security.shiro.permrolemapper.PermissionToRoleMapper;
import org.apache.isis.security.shiro.permrolemapper.PermissionToRoleMapperFromIni;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.ldap.JndiLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.StringUtils;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

/**
 * Implementation of {@link org.apache.shiro.realm.ldap.JndiLdapRealm} that also
 * returns each user's groups.
 * 
 * <p>
 * Sample config for <tt>shiro.ini</tt>:
 * 
 * <pre>
 * contextFactory = IsisLdapContextFactory
 * contextFactory.url = ldap://localhost:10389
 * contextFactory.authenticationMechanism = CRAM-MD5
 * contextFactory.systemAuthenticationMechanism = simple
 * contextFactory.systemUsername = uid=admin,ou=system
 * contextFactory.systemPassword = secret
 * 
 * ldapRealm = IsisLdapRealm
 * ldapRealm.contextFactory = $contextFactory
 * 
 * ldapRealm.searchBase = ou=groups,o=mojo
 * ldapRealm.groupObjectClass = groupOfUniqueNames
 * ldapRealm.uniqueMemberAttribute = uniqueMember
 * ldapRealm.uniqueMemberAttributeValueTemplate = uid={0}
 *
 * # optional mapping from physical groups to logical application roles
 * ldapRealm.rolesByGroup = \
 *    LDN_USERS: user_role,\
 *    NYK_USERS: user_role,\
 *    HKG_USERS: user_role,\
 *    GLOBAL_ADMIN: admin_role,\
 *    DEMOS: self-install_role
 * 
 * securityManager.realms = $ldapRealm
 * </pre>
 * 
 * <p>
 * The permissions for each role can be specified using the
 * {@link #setResourcePath(String)} to an 'ini' file with a [roles] section, eg:
 * 
 * <pre>
 * ldapRealm.resourcePath=classpath:webapp/myroles.ini
 * </pre>
 *
 * <p>
 * where <tt>myroles.ini</tt> is in <tt>src/main/resources/webapp</tt>, and takes the form:
 * 
 * <pre>
 * [roles]
 * user_role = *:ToDoItemsJdo:*:*,\
 *             *:ToDoItem:*:*
 * self-install_role = *:ToDoItemsFixturesService:install:*
 * admin_role = *
 * </pre>
 * 
 * <p>
 * This 'ini' file can then be referenced by other realms (if multiple realm are configured
 * with the Shiro security manager). 
 * 
 * <p>
 * Alternatively, permissions can be set directly using {@link #setPermissionsByRole(String)},
 * where the string is the same information, formatted thus:
 * 
 * <re>
 * ldapRealm.permissionsByRole=\
 *    user_role = *:ToDoItemsJdo:*:*,\
 *                *:ToDoItem:*:*; \
 *    self-install_role = *:ToDoItemsFixturesService:install:* ; \
 *    admin_role = *
 * </pre>
 */
public class IsisLdapRealm extends JndiLdapRealm {

    private static final String UNIQUEMEMBER_SUBSTITUTION_TOKEN = "{0}";
    private final static SearchControls SUBTREE_SCOPE = new SearchControls();
    static {
        SUBTREE_SCOPE.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    private String searchBase;
    private String groupObjectClass;
    private String uniqueMemberAttribute = "uniqueMember";
    private String uniqueMemberAttributeValuePrefix;
    private String uniqueMemberAttributeValueSuffix;
    
    private final Map<String,String> rolesByGroup = Maps.newLinkedHashMap();
    
    private PermissionToRoleMapper permissionToRoleMapper;

    public IsisLdapRealm() {
        setGroupObjectClass("groupOfUniqueNames");
        setUniqueMemberAttribute("uniqueMember");
        setUniqueMemberAttributeValueTemplate("uid={0}");
    }

    @Override
    protected String getUserDnPrefix() {
        return super.getUserDnPrefix();
    }

    /**
     * Get groups from LDAP.
     * 
     * @param principals
     *            the principals of the Subject whose AuthenticationInfo should
     *            be queried from the LDAP server.
     * @param ldapContextFactory
     *            factory used to retrieve LDAP connections.
     * @return an {@link AuthorizationInfo} instance containing information
     *         retrieved from the LDAP server.
     * @throws NamingException
     *             if any LDAP errors occur during the search.
     */
    @Override
    protected AuthorizationInfo queryForAuthorizationInfo(final PrincipalCollection principals, final LdapContextFactory ldapContextFactory) throws NamingException {
        final Set<String> roleNames = getRoles(principals, ldapContextFactory);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo(roleNames);
        Set<String> stringPermissions = permsFor(roleNames);
        simpleAuthorizationInfo.setStringPermissions(stringPermissions);
        return simpleAuthorizationInfo;
    }

    private Set<String> getRoles(final PrincipalCollection principals, final LdapContextFactory ldapContextFactory) throws NamingException {
        final String username = (String) getAvailablePrincipal(principals);

        LdapContext systemLdapCtx = null;
        try {
            systemLdapCtx = ldapContextFactory.getSystemLdapContext();
            return rolesFor(username, systemLdapCtx);
        } catch (AuthenticationException ex) {
            // principal was not authenticated on LDAP
            return Collections.emptySet();
        } finally {
            LdapUtils.closeContext(systemLdapCtx);
        }
    }

    private Set<String> rolesFor(final String userName, final LdapContext ldapCtx) throws NamingException {
        final Set<String> roleNames = Sets.newLinkedHashSet();
        final NamingEnumeration<SearchResult> searchResultEnum = ldapCtx.search(searchBase, "objectClass="+groupObjectClass, SUBTREE_SCOPE);
        while (searchResultEnum.hasMore()) {
            final SearchResult group = searchResultEnum.next();
            addRoleIfMember(userName, group, roleNames);
        }
        return roleNames;
    }

    private void addRoleIfMember(final String userName, final SearchResult group, final Set<String> roleNames) throws NamingException {
        final NamingEnumeration<? extends Attribute> attributeEnum = group.getAttributes().getAll();
        while (attributeEnum.hasMore()) {
            final Attribute attr = attributeEnum.next();
            if (!uniqueMemberAttribute.equalsIgnoreCase(attr.getID())) {
                continue;
            }
            final NamingEnumeration<?> e = attr.getAll();
            while (e.hasMore()) {
                String attrValue = e.next().toString();
                if ((uniqueMemberAttributeValuePrefix + userName + uniqueMemberAttributeValueSuffix).equals(attrValue)) {
                    Attribute attribute = group.getAttributes().get("cn");
                    String groupName = attribute.get().toString();
                    String roleName = roleNameFor(groupName);
                    if(roleName != null) {
                        roleNames.add(roleName);
                    }
                    break;
                }
            }
        }
    }

    private String roleNameFor(String groupName) {
        return !rolesByGroup.isEmpty() ? rolesByGroup.get(groupName) : groupName;
    }


    private Set<String> permsFor(Set<String> roleNames) {
        Set<String> perms = Sets.newLinkedHashSet(); // preserve order
        for(String role: roleNames) {
            List<String> permsForRole = getPermissionsByRole().get(role);
            if(permsForRole != null) {
                perms.addAll(permsForRole);
            }
        }
        return perms;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    public void setGroupObjectClass(String groupObjectClassAttribute) {
        this.groupObjectClass = groupObjectClassAttribute;
    }

    public void setUniqueMemberAttribute(String uniqueMemberAttribute) {
        this.uniqueMemberAttribute = uniqueMemberAttribute;
    }
    
    
    public void setUniqueMemberAttributeValueTemplate(String template) {
        if (!StringUtils.hasText(template)) {
            String msg = "User DN template cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        int index = template.indexOf(UNIQUEMEMBER_SUBSTITUTION_TOKEN);
        if (index < 0) {
            String msg = "UniqueMember attribute value template must contain the '" +
                    UNIQUEMEMBER_SUBSTITUTION_TOKEN + "' replacement token to understand how to " +
                    "parse the group members.";
            throw new IllegalArgumentException(msg);
        }
        String prefix = template.substring(0, index);
        String suffix = template.substring(prefix.length() + UNIQUEMEMBER_SUBSTITUTION_TOKEN.length());
        this.uniqueMemberAttributeValuePrefix = prefix;
        this.uniqueMemberAttributeValueSuffix = suffix;
    }

    public void setRolesByGroup(Map<String, String> rolesByGroup) {
        this.rolesByGroup.putAll(rolesByGroup);
    }

    /**
     * Retrieves permissions by role set using either
     * {@link #setPermissionsByRole(String)} or {@link #setResourcePath(String)}.
     */
    private Map<String,List<String>> getPermissionsByRole() {
        if(permissionToRoleMapper == null) {
            throw new IllegalStateException("Permissions by role not yet set.");
        } 
        return permissionToRoleMapper.getPermissionsByRole();
    }
    
    /**
     * <pre>
     * ldapRealm.resourcePath=classpath:webapp/myroles.ini
     * </pre>
     *
     * <p>
     * where <tt>myroles.ini</tt> is in <tt>src/main/resources/webapp</tt>, and takes the form:
     * 
     * <pre>
     * [roles]
     * user_role = *:ToDoItemsJdo:*:*,\
     *             *:ToDoItem:*:*
     * self-install_role = *:ToDoItemsFixturesService:install:*
     * admin_role = *
     * </pre>
     * 
     * <p>
     * This 'ini' file can then be referenced by other realms (if multiple realm are configured
     * with the Shiro security manager). 
     * 
     * @see #setResourcePath(String)
     */
    public void setResourcePath(String resourcePath) {
        if(permissionToRoleMapper != null) {
            throw new IllegalStateException("Permissions already set, " + permissionToRoleMapper.getClass().getName());
        } 
        final Ini ini = Ini.fromResourcePath(resourcePath);
        this.permissionToRoleMapper = new PermissionToRoleMapperFromIni(ini);
    }

    /**
     * Specify permissions for each role using a formatted string.
     *
     * <pre>
     * ldapRealm.permissionsByRole=\
     *    user_role = *:ToDoItemsJdo:*:*,\
     *                *:ToDoItem:*:*; \
     *    self-install_role = *:ToDoItemsFixturesService:install:* ; \
     *    admin_role = *
     * </pre>
     * 
     * @see #setResourcePath(String)
     */
    @Deprecated
    public void setPermissionsByRole(String permissionsByRoleStr) {
        if(permissionToRoleMapper != null) {
            throw new IllegalStateException("Permissions already set, " + permissionToRoleMapper.getClass().getName());
        } 
        this.permissionToRoleMapper = new PermissionToRoleMapperFromString(permissionsByRoleStr);
    }


}
