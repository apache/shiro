package org.jsecurity.authc;

import org.jsecurity.authz.AuthorizationContext;

/**
 * @author Les Hazlewood
 */
public interface Authenticator {

    /**
     *
     * @param token
     * @return
     * @throws AuthenticationException
     *
     * @see ExpiredCredentialException
     * @see IncorrectCredentialException
     * @see ExcessiveAttemptsException
     * @see LockedAccountException
     * @see ConcurrentAccessException
     * @see UnknownAccountException
     */
    public AuthorizationContext authenticate( AuthenticationToken token ) throws AuthenticationException;
}
