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
import org.jsecurity.authc.credential.AllowAllCredentialsMatcher;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;
import org.jsecurity.subject.Subject;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;

import java.net.InetAddress;
import java.net.UnknownHostException;
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
            fail( "Error creating localhost" );
        }
    }

    @Before
    public void setup() {
        realm = new AllowAllRealm();
        securityManager = new DefaultSecurityManager();
        // Not using constructor to prevent init() from running automatically (so tests can alter SM before init())
        // Tests must call init() on SM before using.
        securityManager.setRealm( realm );

    }

    @After
    public void tearDown() {
        securityManager.destroy();
        securityManager = null;
        realm = null;
    }

    //TODO - re-enable
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
        Object principals = subject.getPrincipal();
        assertTrue(principals instanceof Collection && ((Collection)principals).size() == 3);

        UsernamePrincipal usernamePrincipal = subject.getPrincipals().oneByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = subject.getPrincipals().oneByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        String stringPrincipal = subject.getPrincipals().oneByType(String.class);
        assertTrue(stringPrincipal.equals(USER_ID + USERNAME));


        subject.logout();
    }

    //TODO - re-enable
    public void testCreateAccountOverride() {

        Realm realm = new AllowAllRealm() {
            protected Account createAccount(Object principal, Object credentials) {
                String username = (String) principal;
                UsernamePrincipal customPrincipal = new UsernamePrincipal( username );
                SimplePrincipalCollection principals = new SimplePrincipalCollection("allowAll",customPrincipal);
                return new SimpleAuthorizingAccount( principals, credentials );
            }
        };

        securityManager.setRealm( realm );
        securityManager.init();

        // Do login
        Subject subject = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));
        assertTrue( (subject.getPrincipal() instanceof UsernamePrincipal) );
        assertEquals( USERNAME, ((UsernamePrincipal) subject.getPrincipal()).getUsername() );


    }

    public class AllowAllRealm extends AuthorizingRealm {

        CredentialsMatcher credentialsMatcher;

        public AllowAllRealm() {
            super();
            setCredentialsMatcher( new AllowAllCredentialsMatcher() );
        }

        protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
            PrincipalCollection principals = new SimplePrincipalCollection("allowAll", token.getPrincipal() );
            return doGetAccount( principals );
        }

        protected AuthorizingAccount doGetAccount(PrincipalCollection principals) {
            Set<String> roles = new HashSet<String>();
            roles.add(ROLE);
            return new SimpleAuthorizingAccount(principals, null, roles, new HashSet<Permission>());
        }

        protected Account createAccount(Object principal, Object credentials) {
            SimplePrincipalCollection principals = new SimplePrincipalCollection();
            principals.add( "allowAll", new UserIdPrincipal(USER_ID));
            principals.add( "allowAll", new UsernamePrincipal(USERNAME));
            principals.add( "allowAll", USER_ID + USERNAME );
            return new SimpleAccount(principals,PASSWORD);
        }
    }

}