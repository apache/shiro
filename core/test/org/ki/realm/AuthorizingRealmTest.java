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
package org.ki.realm;

import org.ki.authc.*;
import org.ki.authc.credential.AllowAllCredentialsMatcher;
import org.ki.authc.credential.CredentialsMatcher;
import org.ki.authz.AuthorizationInfo;
import org.ki.authz.Permission;
import org.ki.authz.SimpleAuthorizationInfo;
import org.ki.authz.UnauthorizedException;
import org.ki.authz.permission.WildcardPermission;
import org.ki.mgt.DefaultSecurityManager;
import org.ki.subject.PrincipalCollection;
import org.ki.subject.SimplePrincipalCollection;
import org.ki.subject.Subject;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.*;

/**
 * Simple test case for AuthorizingRealm.
 *
 * TODO - this could/should be expaned to be more robust end to end test for the AuthorizingRealm
 *
 * @author Tim Veil
 */
public class AuthorizingRealmTest {

    DefaultSecurityManager securityManager = null;
    AuthorizingRealm realm;

    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "password";
    private static final int USER_ID = 12345;
    private static final String ROLE = "admin";
    private InetAddress localhost;

    {
        try {
            localhost = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            fail("Error creating localhost");
        }
    }

    @Before
    public void setup() {
        realm = new AllowAllRealm();
        securityManager = new DefaultSecurityManager();
        // Not using constructor to prevent init() from running automatically (so tests can alter SM before init())
        // Tests must call init() on SM before using.
        securityManager.setRealm(realm);

    }

    @After
    public void tearDown() {
        securityManager.destroy();
        securityManager = null;
        realm = null;
    }

    @Test
    public void testDefaultConfig() {
        InetAddress localhost = null;
        try {
            localhost = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        Subject subject = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));
        Object principals = subject.getPrincipal();
        assertTrue(principals instanceof UserIdPrincipal);

        UsernamePrincipal usernamePrincipal = subject.getPrincipals().oneByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = subject.getPrincipals().oneByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        String stringPrincipal = subject.getPrincipals().oneByType(String.class);
        assertTrue(stringPrincipal.equals(USER_ID + USERNAME));


        subject.logout();
    }

    @Test
    public void testCreateAccountOverride() {

        Realm realm = new AllowAllRealm() {
            @Override
            protected AuthenticationInfo buildAuthenticationInfo(Object principal, Object credentials) {
                String username = (String) principal;
                UsernamePrincipal customPrincipal = new UsernamePrincipal(username);
                return new SimpleAccount(customPrincipal, credentials, getName());
            }
        };

        securityManager.setRealm(realm);

        // Do login
        Subject subject = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));
        assertTrue((subject.getPrincipal() instanceof UsernamePrincipal));
        assertEquals(USERNAME, ((UsernamePrincipal) subject.getPrincipal()).getUsername());


    }

    @Test
    public void testNullAuthzInfo() {
        Realm realm = new AuthorizingRealm() {
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

        CredentialsMatcher credentialsMatcher;

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