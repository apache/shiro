/*
 * Copyright 2005-2008 Tim Veil
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity;

import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.activedirectory.ActiveDirectoryRealm;
import org.jsecurity.realm.ldap.LdapContextFactory;
import org.jsecurity.subject.Subject;
import org.junit.After;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Simple test case for ActiveDirectoryRealm.
 *
 * todo:  While the original incarnation of this test case does not actually test the
 * heart of ActiveDirectoryRealm (no meaningful implemenation of queryForLdapAccount, etc) it obviously should.
 * This version was intended to mimic my current usage scenario in an effort to debug upgrade issues which were not related
 * to LDAP connectivity.
 *
 * @author Tim Veil
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
        realm = new TestActiveDirectoryRealm();
        securityManager = new DefaultSecurityManager(realm);

    }

    @After
    public void tearDown() {
        securityManager.destroy();
    }

    @Test
    public void testDefaultConfig() {
        securityManager.init();
        InetAddress localhost = null;
        try {
            localhost = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        Subject subject = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));



        UsernamePrincipal usernamePrincipal = subject.getPrincipals().oneByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));



        UserIdPrincipal userIdPrincipal = subject.getPrincipals().oneByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        Object principals = subject.getPrincipal();

        assertTrue( principals instanceof Collection && ((Collection)principals).size() == 2);

        assertTrue(realm.hasRole(userIdPrincipal, ROLE));

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
                public boolean doCredentialsMatch(AuthenticationToken object, Account object1) {
                    return true;
                }
            };

            setCredentialsMatcher(credentialsMatcher);
        }


        protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
            SimpleAccount account = (SimpleAccount) super.doGetAccount(token);

            if (account != null) {
                List<Object> principals = new ArrayList<Object>();
                principals.add(new UserIdPrincipal(USER_ID));
                principals.add(new UsernamePrincipal(USERNAME));
                account.setPrincipal( principals );
            }

            return account;

        }

        protected AuthorizingAccount doGetAccount(Object principal) {
            Set<String> roles = new HashSet<String>();
            roles.add(ROLE);
            return new SimpleAuthorizingAccount(principal, null, roles, null);
        }

        // override ldap query because i don't care about testing that piece in this case
        protected Account queryForLdapAccount(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {
            return new SimpleAccount(token.getPrincipal(), token.getPrincipal());
        }

    }


}