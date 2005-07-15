package org.jsecurity.authz;

/**
 * Thrown to indicate a requested operation or access to a requested resource is not allowed.
 *
 * @author Les Hazlewood
 */
public class UnauthorizedException extends AuthorizationException {

    public UnauthorizedException() {
        super();
    }

    public UnauthorizedException( String s ) {
        super( s );
    }

    public UnauthorizedException( Throwable cause ) {
        super( cause );
    }

    public UnauthorizedException( String message, Throwable cause ) {
        super( message, cause );
    }
}
