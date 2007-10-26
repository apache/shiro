package org.jsecurity;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.credential.CredentialMatcher;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.support.SimpleAuthorizationInfo;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.realm.support.AuthorizingRealm;
import org.junit.After;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
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

    @Before
    public void setup() {
        realm = new AllowAllRealm();
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
        SecurityContext secCtx = securityManager.authenticate(new UsernamePasswordToken(USERNAME, PASSWORD, localhost));
        assertTrue(secCtx.isAuthenticated());
        assertTrue(secCtx.hasRole(ROLE));
        assertTrue(secCtx.getAllPrincipals().size() == 3);

        UsernamePrincipal usernamePrincipal = (UsernamePrincipal) secCtx.getPrincipalByType(UsernamePrincipal.class);
        assertTrue(usernamePrincipal.getUsername().equals(USERNAME));

        UserIdPrincipal userIdPrincipal = (UserIdPrincipal) secCtx.getPrincipalByType(UserIdPrincipal.class);
        assertTrue(userIdPrincipal.getUserId() == USER_ID);

        String stringPrincipal = (String)secCtx.getPrincipalByType(String.class);
        assertTrue(stringPrincipal.equals(USER_ID + USERNAME));


        secCtx.invalidate();
    }

    public class AllowAllRealm extends AuthorizingRealm {

        /*--------------------------------------------
        |         C O N S T R U C T O R S           |
            ============================================*/
        CredentialMatcher credentialMatcher;

        public AllowAllRealm() {
            super();


            credentialMatcher = new CredentialMatcher() {
                public boolean doCredentialsMatch(Object object, Object object1) {
                    return true;
                }
            };

            setCredentialMatcher(credentialMatcher);
        }

        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

            List<Object> principals = new ArrayList<Object>();
            principals.add(new UserIdPrincipal(USER_ID));
            principals.add(new UsernamePrincipal(USERNAME));
            principals.add(USER_ID + USERNAME);

            return new SimpleAuthenticationInfo(principals, null);
        }

        protected AuthorizationInfo doGetAuthorizationInfo(Object principal) {
            List<String> roles = new ArrayList<String>();
            roles.add(ROLE);
            return new SimpleAuthorizationInfo(roles, new ArrayList<Permission>());
        }
    }


}