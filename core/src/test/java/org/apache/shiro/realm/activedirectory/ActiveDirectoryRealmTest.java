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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.UserIdPrincipal;
import org.apache.shiro.realm.UsernamePrincipal;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertTrue;


/**
 * Simple test case for ActiveDirectoryRealm.
 * <p/>
 * todo:  While the original incarnation of this test case does not actually test the
 * heart of ActiveDirectoryRealm (no meaningful implemenation of queryForLdapAccount, etc) it obviously should.
 * This version was intended to mimic my current usage scenario in an effort to debug upgrade issues which were not related
 * to LDAP connectivity.
 *
 */
public class ActiveDirectoryRealmTest {

    DefaultSecurityManager securityManager = null;
    AuthorizingRealm realm;

    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "password";
    private static final int USER_ID = 12345;
    private static final String ROLE = "admin";

    @Before
    public void setup() {
        ThreadContext.remove();
        realm = new TestActiveDirectoryRealm();
        securityManager = new DefaultSecurityManager(realm);
        SecurityUtils.setSecurityManager(securityManager);
    }

    @After
    public void tearDown() {
        SecurityUtils.setSecurityManager(null);
        securityManager.destroy();
        ThreadContext.remove();
    }

    @Test
    public void testDefaultConfig() {
        String localhost = "localhost";
        Subject subject = SecurityUtils.getSubject();
        subject.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));


        UsernamePrincipal usernamePrincipal = subject.getPrincipals().oneByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = subject.getPrincipals().oneByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        assertTrue(realm.hasRole(subject.getPrincipals(), ROLE));

        subject.logout();
    }

    public class TestActiveDirectoryRealm extends ActiveDirectoryRealm {

        /*--------------------------------------------
        |         C O N S T R U C T O R S           |
            ============================================*/
        CredentialsMatcher credentialsMatcher;

        public TestActiveDirectoryRealm() {
            super();


            credentialsMatcher = new CredentialsMatcher() {
                public boolean doCredentialsMatch(AuthenticationToken object, AuthenticationInfo object1) {
                    return true;
                }
            };

            setCredentialsMatcher(credentialsMatcher);
        }


        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
            SimpleAccount account = (SimpleAccount) super.doGetAuthenticationInfo(token);

            if (account != null) {
                SimplePrincipalCollection principals = new SimplePrincipalCollection();
                principals.add(new UserIdPrincipal(USER_ID), getName());
                principals.add(new UsernamePrincipal(USERNAME), getName());
                account.setPrincipals(principals);
            }

            return account;

        }

        protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
            Set<String> roles = new HashSet<String>();
            roles.add(ROLE);
            return new SimpleAuthorizationInfo(roles);
        }

        // override ldap query because i don't care about testing that piece in this case
        protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {
            return new SimpleAccount(token.getPrincipal(), token.getCredentials(), getName());
        }

    }

}