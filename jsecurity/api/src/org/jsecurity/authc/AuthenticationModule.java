package org.jsecurity.authc;

/**
 * @author Les Hazlewood
 */
public interface AuthenticationModule extends Authenticator {

    boolean supports( Class tokenClass );

}
