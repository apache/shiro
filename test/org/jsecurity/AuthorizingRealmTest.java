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
import org.jsecurity.subject.Subject;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
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
        realm.destroy();
        realm = null;
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
        Object principals = subject.getPrincipal();
        assertTrue(principals instanceof Collection && ((Collection)principals).size() == 3);

        UsernamePrincipal usernamePrincipal = subject.getPrincipalByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = subject.getPrincipalByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        String stringPrincipal = subject.getPrincipalByType(String.class);
        assertTrue(stringPrincipal.equals(USER_ID + USERNAME));


        subject.logout();
    }

    @Test
    public void testCreateAccountOverride() {

        Realm realm = new AllowAllRealm() {
            protected Account createAccount(Object principal, Object credentials) {
                String username = (String) principal;
                CustomUsernamePrincipal customPrincipal = new CustomUsernamePrincipal( username );
                return new SimpleAuthorizingAccount( customPrincipal, credentials );
            }
        };

        securityManager.setRealm( realm );
        securityManager.init();

        // Do login
        Subject subject = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(subject.isAuthenticated());
        assertTrue(subject.hasRole(ROLE));
        assertTrue( (subject.getPrincipal() instanceof CustomUsernamePrincipal) );
        assertEquals( USERNAME, ((CustomUsernamePrincipal) subject.getPrincipal()).getUsername() );


    }

    public class AllowAllRealm extends AuthorizingRealm {

        CredentialsMatcher credentialsMatcher;

        public AllowAllRealm() {
            super();
            setCredentialsMatcher( new AllowAllCredentialsMatcher() );
        }

        protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
            return doGetAccount( token.getPrincipal() );
        }

        protected AuthorizingAccount doGetAccount(Object principal) {
            Set<String> roles = new HashSet<String>();
            roles.add(ROLE);
            return new SimpleAuthorizingAccount(principal, null, roles, new HashSet<Permission>());
        }

        protected Account createAccount(Object principal, Object credentials) {
            List<Object> principals = new ArrayList<Object>();
            principals.add(new UserIdPrincipal(USER_ID));
            principals.add(new UsernamePrincipal(USERNAME));
            principals.add(USER_ID + USERNAME);
            return new SimpleAccount(principals,null);
        }
    }

    public class CustomUsernamePrincipal {
        private String username;

        public CustomUsernamePrincipal(String username) {
            this.username = username;
        }

        public String getUsername() {
            return username;
        }
    }

}