package org.jsecurity.subject;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface RememberMeManager {

    Object getRememberedIdentity();

    void onSuccessfulLogin( AuthenticationToken token, Account account );

    void onFailedLogin( AuthenticationToken token, AuthenticationException ae );

    void onLogout( Object subjectPrincipals );
}
