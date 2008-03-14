package org.jsecurity.subject;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * A RememberMeManager is responsible for remembering a Subject's identity across that subject's sessions with
 * the application.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface RememberMeManager {

    Object getRememberedIdentity();

    void onSuccessfulLogin( AuthenticationToken token, Account account );

    void onFailedLogin( AuthenticationToken token, AuthenticationException ae );

    void onLogout( Object subjectPrincipals );
}
