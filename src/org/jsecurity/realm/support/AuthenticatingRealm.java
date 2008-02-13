package org.jsecurity.realm.support;

import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authc.credential.SimpleCredentialsMatcher;
import org.jsecurity.authc.support.SimpleAccount;
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
    protected CredentialsMatcher credentialsMatcher = new SimpleCredentialsMatcher();

    /**
     * The class that this realm supports for authentication tokens.  This is used by the
     * default implementation of the {@link #supports(Class)} method to determine whether or not the
     * given authentication token is supported by this realm.
     */
    protected Class<? extends AuthenticationToken> authenticationTokenClass = UsernamePasswordToken.class;


    /*--------------------------------------------
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

    public AuthenticatingRealm( String name, CredentialsMatcher matcher ) {
        this( name );
        setCredentialsMatcher( matcher );
    }

    public AuthenticatingRealm( String name, CacheProvider cacheProvider, CredentialsMatcher matcher ) {
        this( name, cacheProvider );
        setCredentialsMatcher( matcher );
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public CredentialsMatcher getCredentialsMatcher() {
        return credentialsMatcher;
    }

    /**
     * Sets the CrendialsMatcher implementation to use to verify submitted credentials with those stored in the system
     * for a given authentication attempt.  The implementation of this matcher can be switched via configuration to
     * support any number of schemes, including plain text comparisons, hashing comparisons, and others.
     *
     * <p>Unless overridden by this method, the default value is a {@link org.jsecurity.authc.credential.SimpleCredentialsMatcher} instance.
     *
     * @param credentialsMatcher the matcher to use.
     */
    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        this.credentialsMatcher = credentialsMatcher;
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
     * This method must be implemented by subclasses to retrieve account data from an
     * implementation-specific datasource (RDBMS, LDAP, etc) for the given authentication token.
     * In most data-centric systems such as an RDBMS, LDAP, file resource, etc, this means just 'pulling'
     * account data for an associated subject/user.  But in some systems (mainframe, etc), the method
     * could actually perform EIS specific log-in logic - it is up to the realm implementation.
     *
     * <p>A <tt>null</tt> return value means that no account could be associated with the specified token.
     *
     * @param token the authentication token containing the user's principal and credentials.
     * @return an {@link org.jsecurity.authc.Account} object containing account information resulting from the
     * authentication ONLY if the lookup is successful (i.e. account exists and is valid, etc.)
     * @throws org.jsecurity.authc.AuthenticationException if there is an error acquiring data or performing
     * realm-specific authentication logic for the specified <tt>token</tt>
     */
    protected abstract Account doGetAccount( AuthenticationToken token ) throws AuthenticationException;

    /**
     * Primarily used to acquire a string to display in exceptions and logging.  Default implementation
     * returns a value based on account.getPrincipal();
     *
     * <p>If overridding, be careful to not include any private credentials (such as passwords or private keys) if this
     * information should not show up in log entries or error messages.
     * @param account account after a successful authentication attempt.
     * @return String representation of the given account that can be used in exceptions and logging.
     */
    protected String displayName( Account account) {
        Object  p = account.getPrincipal();
        if ( p != null ) {
            return p.toString();
        } else {
            return account.toString();
        }
    }

    public final Account getAccount( AuthenticationToken token ) throws AuthenticationException {

        Account account = doGetAccount( token );

        if( account == null ) {
            if ( log.isDebugEnabled() ) {
                String msg = "No account information found for submitted authentication token [" + token + "].  " +
                "Returning null.";
                log.debug( msg );
            }
            return null;
        }

        if ( account.isLocked() ) {
            throw new LockedAccountException( "Account [" + displayName( account ) + "] is locked." );
        }
        if ( account.isCredentialsExpired() ) {
            String msg = "The credentials for account [" + displayName( account ) + "] are expired";
            throw new ExpiredCredentialException( msg );
        }

        CredentialsMatcher cm = getCredentialsMatcher();
        if ( cm != null ) {
            if ( !cm.doCredentialsMatch( token, account ) ) {
                String msg = "The credentials provided for account [" + token +
                             "] did not match the expected credentials.";
                throw new IncorrectCredentialException( msg );
            }
        } else {
            throw new AuthenticationException( "A CredentialsMatcher must be configured in order to verify " +
                    "credentials during authentication.  If you do not wish for credentials to be examined, you " +
                    "can configure an AllowAllCredentialsMatcher." );
        }

        return account;
    }

    /**
     * <p>This is a convenience method that is used by many of the JSecurity built-in realms.  It can be overridden
     * by subclasses to build the {@link org.jsecurity.authc.Account} in a different way.</p>
     *
     * <p>Overriding this method is the prefered way of building a custom {@link org.jsecurity.authc.Account} object
     * for realms that make use of this helper method.</p>
     * @param principal the principal of the authenticated user.
     * @param credentials the credentials of the authenticated user.
     * @return an {@link org.jsecurity.authc.Account} instance that should be used to "log in" the user.
     */
    protected Account createAccount( Object principal, Object credentials ) {
        return new SimpleAccount(principal, credentials);
    }
}
