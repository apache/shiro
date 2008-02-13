package org.jsecurity;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authc.support.SimpleAccount;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.support.SimpleAuthorizationInfo;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.support.AuthorizingRealm;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Simple test case for AuthorizingRealm.
 *
 * todo:  this is a very simple test designed to mimic the AllowAllRealm approach we have been using lately
 * this could/should be expaned to be more robust end to end test for the AuthorizingRealm
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
        SecurityContext secCtx = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(secCtx.isAuthenticated());
        assertTrue(secCtx.hasRole(ROLE));
        Object principals = secCtx.getPrincipal();
        assertTrue(principals instanceof Collection && ((Collection)principals).size() == 3);

        UsernamePrincipal usernamePrincipal = (UsernamePrincipal) secCtx.getPrincipalByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = (UserIdPrincipal) secCtx.getPrincipalByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        String stringPrincipal = (String)secCtx.getPrincipalByType(String.class);
        assertTrue(stringPrincipal.equals(USER_ID + USERNAME));


        secCtx.logout();
    }

    @Test
    public void testCreateAccountOverride() {

        Realm realm = new AllowAllRealm() {
            protected Account createAccount(Object principal, Object credentials) {
                String username = (String) principal;
                CustomUsernamePrincipal customPrincipal = new CustomUsernamePrincipal( username );
                return new SimpleAccount( customPrincipal, credentials );
            }
        };

        securityManager.setRealm( realm );
        securityManager.init();

        // Do login
        SecurityContext secCtx = securityManager.login(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(secCtx.isAuthenticated());
        assertTrue(secCtx.hasRole(ROLE));
        assertTrue( (secCtx.getPrincipal() instanceof CustomUsernamePrincipal) );
        assertEquals( USERNAME, ((CustomUsernamePrincipal) secCtx.getPrincipal()).getUsername() );


    }

    public class AllowAllRealm extends AuthorizingRealm {

        /*--------------------------------------------
        |         C O N S T R U C T O R S           |
            ============================================*/
        CredentialsMatcher credentialsMatcher;

        public AllowAllRealm() {
            super();


            credentialsMatcher = new CredentialsMatcher() {
                public boolean doCredentialsMatch(AuthenticationToken object, Account object1) {
                    return true;
                }
            };

            setCredentialsMatcher(credentialsMatcher);
        }

        protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
            UsernamePasswordToken upToken = (UsernamePasswordToken) token;
            return createAccount(token.getPrincipal(), token.getPrincipal());
        }

        protected AuthorizationInfo doGetAuthorizationInfo(Object principal) {
            List<String> roles = new ArrayList<String>();
            roles.add(ROLE);
            return new SimpleAuthorizationInfo(roles, new ArrayList<Permission>());
        }

        protected Account createAccount(Object principal, Object credentials) {

            List<Object> principals = new ArrayList<Object>();
            principals.add(new UserIdPrincipal(USER_ID));
            principals.add(new UsernamePrincipal(USERNAME));
            principals.add(USER_ID + USERNAME);

            return createAccount(principals, null);
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