package org.jsecurity.realm.support;

import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.CredentialMatcher;
import org.jsecurity.authc.credential.support.PlainTextCredentialMatcher;
import org.jsecurity.cache.CacheProvider;

/**
 * A top-level abstract implementation of the <tt>Realm</tt> interface that only implements authentication support
 * (log-in) operations and leaves authorization (access control) behavior to subclasses.
 *
 * <p>Since a realm provides both authentication <em>and</em> authorization operations, the implementation approach for
 * this class could have been reversed.  That is, authorization support could have been implemented here and
 * authentication support left to subclasses.
 *
 * <p>The reason the existing implementation is in place though
 * (authentication support) is that most authentication operations are fairly common across the large majority of
 * applications, whereas authorization operations are more so heavily dependent upon the application's data model, which
 * varies widely.
 *
 * <p>By providing the most common authentication operations here and leaving data-model specific checks to subclasses,
 * a top-level abstract class for most common authentication behavior is more useful as an extension point (rather
 * than the other way around).
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class AuthenticatingRealm extends AbstractRealm {

    /**
     * Password matcher used to determine if the provided password matches
     * the password stored in the data store.
     */
    protected CredentialMatcher credentialMatcher = new PlainTextCredentialMatcher();

    /**
     * The class that this realm supports for authentication tokens.  This is used by the
     * default implementation of the {@link #supports(Class)} method to determine whether or not the
     * given authentication token is supported by this realm.
     */
    protected Class<? extends AuthenticationToken> authenticationTokenClass = UsernamePasswordToken.class;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*//*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthenticatingRealm() {
        super();
    }

    public AuthenticatingRealm( String name ) {
        super( name );
    }

    public AuthenticatingRealm( String name, CacheProvider cacheProvider ) {
        super( name, cacheProvider );
    }

    public AuthenticatingRealm( String name, CredentialMatcher matcher ) {
        this( name );
        setCredentialMatcher( matcher );
    }

    public AuthenticatingRealm( String name, CacheProvider cacheProvider, CredentialMatcher matcher ) {
        this( name, cacheProvider );
        setCredentialMatcher( matcher );
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public CredentialMatcher getCredentialMatcher() {
        return credentialMatcher;
    }

    /**
     * Sets the CrendialMatcher implementation to use to verify submitted credentials with those stored in the system
     * for a given authentication attempt.  The implementation of this matcher can be switched via configuration to
     * support any number of schemes, including plain text password comparison, digest/hashing comparisons, and others.
     *
     * <p>Unless overridden by this method, the default value is a {@link PlainTextCredentialMatcher} instance.
     *
     * @param credentialMatcher the matcher to use.
     */
    public void setCredentialMatcher(CredentialMatcher credentialMatcher) {
        this.credentialMatcher = credentialMatcher;
    }

    /**
     * Returns the authenticationToken class supported by this realm.
     *
     * <p>The default value is <tt>{@link UsernamePasswordToken UsernamePasswordToken.class}</tt>, since
     * about 90% of realms use username/password authentication, regardless of their protocol (e.g. over jdbc, ldap,
     * kerberos, http, etc).
     *
     * <p>Subclasses must override this method if they won't support <tt>UsernamePasswordToken</tt> authentications and
     * they haven't already overridden the {@link #supports} method.
     *
     * @return the authenticationToken class supported by this realm.
     *
     * @see #setAuthenticationTokenClass
     */
    public Class getAuthenticationTokenClass() {
        return authenticationTokenClass;
    }

    /**
     * Sets the authenticationToken class supported by this realm.
     *
     * <p>Unless overridden by this method, the default value is {@link UsernamePasswordToken} to support 90% of
     * application's out of the box.
     *
     * @param authenticationTokenClass the class of authentication token instances supported by this realm.
     *
     * @see #getAuthenticationTokenClass getAuthenticationTokenClass() for more explanation.
     */
    public void setAuthenticationTokenClass(Class<? extends AuthenticationToken> authenticationTokenClass) {
        this.authenticationTokenClass = authenticationTokenClass;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Convenience implementation that returns
     * <tt>getAuthenticationTokenClass().isAssignableFrom( tokenClass );</tt>.  Can be overridden
     * by subclasses for more complex token type checking.
     * <p>Most implementations will only need to set a different class via
     * {@link #setAuthenticationTokenClass}, as opposed to overriding this method.
     *
     * @param tokenClass the class of the authenticationToken being submitted for authentication.
     * @return true if this authentication realm "understands" how to process submissions for the submitted token
     * instances of the class, false otherwise.
     */
    public boolean supports(Class tokenClass) {
        return getAuthenticationTokenClass().isAssignableFrom( tokenClass );
    }

    /**
     * This method must be implemented by subclasses to retrieve authentication information from an
     * implementation-specific datasource (RDBMS, LDAP, etc) for the given authentication token.
     * In most data-centric systems such as an RDBMS, LDAP, file resource, etc, this means just 'pulling'
     * authentication information for an associated subject/user.  But in some systems (mainframe, etc), the method 
     * could actually perform EIS specific log-in logic - it is up to the realm implementation.
     *
     * <p>A <tt>null</tt> return value means that no account could be associated with the specified token.
     *
     * @param token the authentication token containing the user's principal and credentials.
     * @return an {@link org.jsecurity.authc.AuthenticationInfo} object containing user information resulting from the
     * authentication ONLY if the lookup is successful (i.e. account exists and is valid, etc.)
     * @throws org.jsecurity.authc.AuthenticationException if there is an error acquiring data or performing
     * realm-specific authentication logic for the specified <tt>token</tt>
     */
    protected abstract AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException;

    /**
     * Primarily used to acquire a string to display in exceptions and logging.  Default implementation
     * returns a value based on info.getPrincipal();
     *
     * <p>If overridding, be careful to not include any private credentials (such as passwords or private keys) if this
     * information should not show up in log entries or error messages.
     * @param info account info after a successful authentication attempt.
     * @return string representation of the given info that can be used in exceptions and logging.
     */
    protected String displayName( AuthenticationInfo info ) {
        Object  p = info.getPrincipal();
        if ( p != null ) {
            return p.toString();
        } else {
            return info.toString();
        }
    }

    public final AuthenticationInfo getAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {

        AuthenticationInfo info = doGetAuthenticationInfo( token );

        if( info == null ) {
            if ( log.isDebugEnabled() ) {
                String msg = "No account information found for submitted authentication token [" + token + "].  " +
                "Returning null.";
                log.debug( msg );
            }
            return null;
        }

        if ( info.isAccountLocked() ) {
            throw new LockedAccountException( "Account [" + displayName( info ) + "] is locked." );
        }
        if ( info.isCredentialsExpired() ) {
            String msg = "The credentials for account [" + displayName( info ) + "] are expired";
            throw new ExpiredCredentialException( msg );
        }

        CredentialMatcher cm = getCredentialMatcher();
        if ( cm != null ) {
            if ( !cm.doCredentialsMatch( token.getCredentials(), info.getCredentials() ) ) {
                String msg = "The credentials provided for account [" + token +
                             "] did not match the expected credentials.";
                throw new IncorrectCredentialException( msg );
            }
        } else {
            throw new AuthenticationException( "A CredentialMatcher must be configured in order to verify " +
                    "credentials during authentication.  If you do not wish for credentials to be examined, you " +
                    "can configure an AllowAllCredentialMatcher." );
        }

        return info;
    }
}
