package org.jsecurity.authc.pam;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.SimpleAccountRealm;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 29, 2008
 * Time: 12:18:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class AllSuccessfulModularAuthenticationStrategyTest {

    private AllSuccessfulModularAuthenticationStrategy strategy;

    @Before
    public void setUp() {
        strategy = new AllSuccessfulModularAuthenticationStrategy();
    }

    @Test
    public void beforeAllAttempts() {
        Account account = strategy.beforeAllAttempts(null,null);
        assertNotNull(account);
    }

    @Test
    public void beforeAttemptSupportingToken() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.init();
    }

    @Test(expected=UnsupportedTokenException.class)
    public void beforeAttemptRealmDoesntSupportToken() {
        Realm notSupportingRealm = new AuthorizingRealm() {

            public boolean supports(AuthenticationToken token) {
                return false;
            }

            protected AuthorizingAccount doGetAccount(Object principal) {
                return null;
            }

            protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
                return null;
            }
        };

        strategy.beforeAttempt(notSupportingRealm,null,null);
    }


}
