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
package org.apache.shiro.realm;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * Simple test case for AuthorizingRealm.
 * <p/>
 * TODO - this could/should be expanded to be more robust end to end test for the AuthorizingRealm
 */
public class AuthorizingRealmTest {

    AuthorizingRealm realm;

    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "password";
    private static final int USER_ID = 12345;
    private static final String ROLE = "admin";
    private String localhost = "localhost";

    @Before
    public void setup() {
        realm = new AllowAllRealm();

    }

    @After
    public void tearDown() {
        realm = null;
    }

    @Test
    public void testDefaultConfig() {
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));

        assertNotNull(info);
        assertTrue(realm.hasRole(info.getPrincipals(), ROLE));

        Object principal = info.getPrincipals().getPrimaryPrincipal();
        assertTrue(principal instanceof UserIdPrincipal);

        UsernamePrincipal usernamePrincipal = info.getPrincipals().oneByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = info.getPrincipals().oneByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        String stringPrincipal = info.getPrincipals().oneByType(String.class);
        assertTrue(stringPrincipal.equals(USER_ID + USERNAME));
    }

    @Test
    public void testCreateAccountOverride() {

        AuthorizingRealm realm = new AllowAllRealm() {
            @Override
            protected AuthenticationInfo buildAuthenticationInfo(Object principal, Object credentials) {
                String username = (String) principal;
                UsernamePrincipal customPrincipal = new UsernamePrincipal(username);
                return new SimpleAccount(customPrincipal, credentials, getName());
            }
        };

        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertNotNull(info);
        assertTrue(realm.hasRole(info.getPrincipals(), ROLE));
        Object principal = info.getPrincipals().getPrimaryPrincipal();
        assertTrue(principal instanceof UsernamePrincipal);
        assertEquals(USERNAME, ((UsernamePrincipal) principal).getUsername());


    }

    @Test
    public void testNullAuthzInfo() {
	AuthorizingRealm realm = new AuthorizingRealm() {
            protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
                return null;
            }

            protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
                return null;
            }
        };

        Principal principal = new UsernamePrincipal("blah");
        PrincipalCollection pCollection = new SimplePrincipalCollection(principal, "nullAuthzRealm");
        List<Permission> permList = new ArrayList<Permission>();
        permList.add(new WildcardPermission("stringPerm1"));
        permList.add(new WildcardPermission("stringPerm2"));
        List<String> roleList = new ArrayList<String>();
        roleList.add("role1");
        roleList.add("role2");

        boolean thrown = false;
        try {
            realm.checkPermission(pCollection, "stringPermission");
        } catch (UnauthorizedException e) {
            thrown = true;
        }
        assertTrue(thrown);
        thrown = false;

        try {
            realm.checkPermission(pCollection, new WildcardPermission("stringPermission"));
        } catch (UnauthorizedException e) {
            thrown = true;
        }
        assertTrue(thrown);
        thrown = false;

        try {
            realm.checkPermissions(pCollection, "stringPerm1", "stringPerm2");
        } catch (UnauthorizedException e) {
            thrown = true;
        }
        assertTrue(thrown);
        thrown = false;

        try {
            realm.checkPermissions(pCollection, permList);
        } catch (UnauthorizedException e) {
            thrown = true;
        }
        assertTrue(thrown);
        thrown = false;

        try {
            realm.checkRole(pCollection, "role1");
        } catch (UnauthorizedException e) {
            thrown = true;
        }
        assertTrue(thrown);
        thrown = false;

        try {
            realm.checkRoles(pCollection, roleList);
        } catch (UnauthorizedException e) {
            thrown = true;
        }
        assertTrue(thrown);

        assertFalse(realm.hasAllRoles(pCollection, roleList));
        assertFalse(realm.hasRole(pCollection, "role1"));
        assertArrayEquals(new boolean[]{false, false}, realm.hasRoles(pCollection, roleList));
        assertFalse(realm.isPermitted(pCollection, "perm1"));
        assertFalse(realm.isPermitted(pCollection, new WildcardPermission("perm1")));
        assertArrayEquals(new boolean[]{false, false}, realm.isPermitted(pCollection, "perm1", "perm2"));
        assertArrayEquals(new boolean[]{false, false}, realm.isPermitted(pCollection, permList));
        assertFalse(realm.isPermittedAll(pCollection, "perm1", "perm2"));
        assertFalse(realm.isPermittedAll(pCollection, permList));
    }
    
    @Test
    public void testRealmWithRolePermissionResolver()
    {   
        Principal principal = new UsernamePrincipal("rolePermResolver");
        PrincipalCollection pCollection = new SimplePrincipalCollection(principal, "testRealmWithRolePermissionResolver");
        
        AuthorizingRealm realm = new AllowAllRealm();
        realm.setRolePermissionResolver( new RolePermissionResolver()
        { 
            public Collection<Permission> resolvePermissionsInRole( String roleString )
            {
                Collection<Permission> permissions = new HashSet<Permission>();
                if( roleString.equals( ROLE ))
                {
                    permissions.add( new WildcardPermission( ROLE + ":perm1" ) );
                    permissions.add( new WildcardPermission( ROLE + ":perm2" ) );
                    permissions.add( new WildcardPermission( "other:*:foo" ) );
                }
                return permissions;
            }
        });
        
        assertTrue( realm.hasRole( pCollection, ROLE ) );
        assertTrue( realm.isPermitted( pCollection, ROLE + ":perm1" ) );
        assertTrue( realm.isPermitted( pCollection, ROLE + ":perm2" ) );
        assertFalse( realm.isPermitted( pCollection, ROLE + ":perm3" ) );
        assertTrue( realm.isPermitted( pCollection, "other:bar:foo" ) );
    }

    @Test
    public void testRealmWithEmptyOrNullPermissions() {
        Principal principal = new UsernamePrincipal("rolePermResolver");
        PrincipalCollection pCollection = new SimplePrincipalCollection(principal, "testRealmWithRolePermissionResolver");

        AuthorizingRealm realm = new AllowAllRealm();
        realm.setRolePermissionResolver( new RolePermissionResolver()
        {
            public Collection<Permission> resolvePermissionsInRole( String roleString )
            {
                Collection<Permission> permissions = new HashSet<Permission>();
                if( roleString.equals( ROLE ))
                {
                    permissions.add( new WildcardPermission( ROLE + ":perm1" ) );
                    permissions.add( new WildcardPermission( ROLE + ":perm2" ) );
                    permissions.add( new WildcardPermission( ROLE + ": " ) );
                    permissions.add( new WildcardPermission( ROLE + ":\t" ) );
                    permissions.add( new WildcardPermission( "other:*:foo" ) );
                }
                return permissions;
            }
        });

        realm.setPermissionResolver(new WildcardPermissionResolver());
        SimpleAuthorizationInfo authorizationInfo = (SimpleAuthorizationInfo) realm.getAuthorizationInfo(pCollection);
        assertNotNull(authorizationInfo);
        authorizationInfo.addStringPermission("");
        authorizationInfo.addStringPermission(" ");
        authorizationInfo.addStringPermission("\t");
        authorizationInfo.addStringPermission(null);
        Collection<Permission> permissions = realm.getPermissions(authorizationInfo);
        assertEquals(permissions.size(), 4);
    }

    private void assertArrayEquals(boolean[] expected, boolean[] actual) {
        if (expected.length != actual.length) {
            fail("Expected array of length [" + expected.length + "] but received array of length [" + actual.length + "]");
        }
        for (int i = 0; i < expected.length; i++) {
            if (expected[i] != actual[i]) {
                fail("Expected index [" + i + "] to be [" + expected[i] + "] but was [" + actual[i] + "]");
            }
        }
    }

    public class AllowAllRealm extends AuthorizingRealm {

        public AllowAllRealm() {
            super();
            setCredentialsMatcher(new AllowAllCredentialsMatcher());
        }

        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
            return buildAuthenticationInfo(token.getPrincipal(), token.getCredentials());
        }

        protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
            Set<String> roles = new HashSet<String>();
            roles.add(ROLE);
            return new SimpleAuthorizationInfo(roles);
        }

        protected AuthenticationInfo buildAuthenticationInfo(Object principal, Object credentials) {
            Collection<Object> principals = new ArrayList<Object>(3);
            principals.add(new UserIdPrincipal(USER_ID));
            principals.add(new UsernamePrincipal(USERNAME));
            principals.add(USER_ID + USERNAME);
            return new SimpleAuthenticationInfo(principals, PASSWORD, getName());
        }

    }

}
