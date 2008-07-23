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
package org.jsecurity;

import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.AllowAllCredentialsMatcher;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.SimpleAuthorizationInfo;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.Subject;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

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