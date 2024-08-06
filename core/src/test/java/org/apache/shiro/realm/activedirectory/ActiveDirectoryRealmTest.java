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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.UserIdPrincipal;
import org.apache.shiro.realm.UsernamePrincipal;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.subject.ImmutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.easymock.Capture;
import org.easymock.CaptureType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.HashSet;
import java.util.Set;

import static org.apache.shiro.test.AbstractShiroTest.GLOBAL_SECURITY_MANAGER_RESOURCE;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.hamcrest.MatcherAssert.assertThat;

import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.is;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Simple test case for ActiveDirectoryRealm.
 * <p/>
 * todo:  While the original incarnation of this test case does not actually test the
 * heart of ActiveDirectoryRealm (no meaningful implementation of queryForLdapAccount, etc.) it obviously should.
 * This version was intended to mimic my current usage scenario in an effort to debug upgrade issues which were not related
 * to LDAP connectivity.
 */
@ResourceLock(GLOBAL_SECURITY_MANAGER_RESOURCE)
public class ActiveDirectoryRealmTest {

    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "password";
    private static final int USER_ID = 12345;
    private static final String ROLE = "admin";

    DefaultSecurityManager securityManager;
    AuthorizingRealm realm;

    @BeforeEach
    public void setup() {
        ThreadContext.remove();
        realm = new TestActiveDirectoryRealm();
        securityManager = new DefaultSecurityManager(realm);
        SecurityUtils.setSecurityManager(securityManager);
    }

    @AfterEach
    public void tearDown() {
        SecurityUtils.setSecurityManager(null);
        securityManager.destroy();
        ThreadContext.remove();
    }

    @Test
    void testDefaultConfig() {
        String localhost = "localhost";
        Subject subject = SecurityUtils.getSubject();
        subject.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));


        UsernamePrincipal usernamePrincipal = subject.getPrincipals().oneByType(UsernamePrincipal.class);
        assertEquals(USERNAME, usernamePrincipal.getUsername());

        UserIdPrincipal userIdPrincipal = subject.getPrincipals().oneByType(UserIdPrincipal.class);
        assertEquals(USER_ID, userIdPrincipal.getUserId());

        assertTrue(realm.hasRole(subject.getPrincipals(), ROLE));

        subject.logout();
    }

    @Test
    void testExistingUserSuffix() throws Exception {
        // suffix case matches configure suffix
        assertExistingUserSuffix(USERNAME, "testuser@ExAmple.COM");

        // suffix matches user entry
        assertExistingUserSuffix(USERNAME + "@example.com", "testuser@example.com");
        assertExistingUserSuffix(USERNAME + "@EXAMPLE.com", "testuser@EXAMPLE.com");
    }

    public void assertExistingUserSuffix(String username, String expectedPrincipalName) throws Exception {

        LdapContext ldapContext = createMock(LdapContext.class);
        NamingEnumeration<SearchResult> results = createMock(NamingEnumeration.class);
        Capture<Object[]> captureArgs = Capture.newInstance(CaptureType.ALL);
        expect(ldapContext.search(anyString(), anyString(), capture(captureArgs), anyObject(SearchControls.class)))
                .andReturn(results);
        replay(ldapContext);

        ActiveDirectoryRealm activeDirectoryRealm = new ActiveDirectoryRealm() {{
            this.principalSuffix = "@ExAmple.COM";
        }};

        SecurityManager securityManager = new DefaultSecurityManager(activeDirectoryRealm);
        Subject subject = new Subject.Builder(securityManager).buildSubject();
        subject.execute(() -> {

            try {
                activeDirectoryRealm.getRoleNamesForUser(username, ldapContext);
            } catch (NamingException e) {
                fail("Unexpected NamingException thrown during test");
            }
        });

        Object[] args = captureArgs.getValue();
        assertThat(args, arrayWithSize(1));
        assertThat(args[0], is(expectedPrincipalName));
    }

    public static class TestActiveDirectoryRealm extends ActiveDirectoryRealm {

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

        public void setPrincipalSuffix(String principalSuffix) {
            this.principalSuffix = principalSuffix;
        }

        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
            SimpleAccount account = (SimpleAccount) super.doGetAuthenticationInfo(token);

            if (account != null) {
                var principals = new ImmutablePrincipalCollection.Builder();
                principals.addPrincipal(new UserIdPrincipal(USER_ID), getName());
                principals.addPrincipal(new UsernamePrincipal(USERNAME), getName());
                account.setPrincipals(principals.build());
            }

            return account;

        }

        protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
            Set<String> roles = new HashSet<String>();
            roles.add(ROLE);
            return new SimpleAuthorizationInfo(roles);
        }

        // override ldap query because i don't care about testing that piece in this case
        protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory)
                throws NamingException {
            return new SimpleAccount(token.getPrincipal(), token.getCredentials(), getName());
        }

    }

}
