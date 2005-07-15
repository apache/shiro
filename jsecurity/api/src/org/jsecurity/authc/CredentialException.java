package org.jsecurity.authc;

/**
 * Exception thrown due to a problem with the credential(s) submitted for an
 * account during the authentication process.
 *
 * @author Les Hazlewood
 */
public class CredentialException extends AuthenticationException {

    public CredentialException() {
        super();
    }

    public CredentialException( String message ) {
        super( message );
    }

    public CredentialException( Throwable cause ) {
        super( cause );
    }

    public CredentialException( String message, Throwable cause ) {
        super( message, cause );
    }

}
