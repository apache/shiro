package org.jsecurity.authc;

/**
 * Thrown when attempting to authenticate with a credential that does not match the actual
 * credential associated with the account principal.
 *
 * <p>For example, this exception might be thrown if a user's password is &quot;secret&quot; and
 * &quot;secrets&quot; was entered by mistake.  Whether or not an application wishes to let
 * the user know if they entered in an incorrect password is at the discretion of those
 * responsible for defining the view and what happens when this case occurs.
 *
 * @author Les Hazlewood
 */
public class IncorrectCredentialException extends CredentialException {

    public IncorrectCredentialException() {
        super();
    }

    public IncorrectCredentialException( String message ) {
        super( message );
    }

    public IncorrectCredentialException( Throwable cause ) {
        super( cause );
    }

    public IncorrectCredentialException( String message, Throwable cause ) {
        super( message, cause );
    }

}
