package org.jsecurity.authc;

/**
 * Thrown during the authentication process when the system determines the submitted credential
 * has expired and will not allow login.
 *
 * <p>This is most often used to alert a user that their credential (e.g. password or
 * cryptography key) has expired and they should change its value.  In such systems, the component
 * invoking the authentication might catch this exception and redirect the user to an appropriate
 * view to allow them to update their password.
 *
 * @author Les Hazlewood 
 */
public class ExpiredCredentialException extends CredentialException {

    public ExpiredCredentialException() {
        super();
    }

    public ExpiredCredentialException( String message ) {
        super( message );
    }

    public ExpiredCredentialException( Throwable cause ) {
        super( cause );
    }

    public ExpiredCredentialException( String message, Throwable cause ) {
        super( message, cause );
    }
}
