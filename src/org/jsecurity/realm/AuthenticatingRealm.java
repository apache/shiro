package org.jsecurity.realm;

import org.jsecurity.authc.*;
import org.jsecurity.authc.credential.AllowAllCredentialsMatcher;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authc.credential.SimpleCredentialsMatcher;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.cache.CacheProvider;

/**
 * A top-level abstract implementation of the <tt>Realm</tt> interface that only implements authentication support
 * (log-in) operations and leaves authorization (access control) behavior to subclasses.
 *
 * <p>Since a Realm provides both authentication <em>and</em> authorization operations, the implementation approach for
 * this class could have been reversed.  That is, authorization support could have been implemented here and
 * authentication support left to subclasses.
 *
 * <p>The reason the existing implementation is in place though
 * (authentication support) is that most authentication operations are fairly common across the large majority of
 * applications, whereas authorization operations are more so heavily dependent upon the application's data model, which
 * can vary widely.
 *
 * <p>By providing the most common authentication operations here and leaving data-model specific checks to subclasses,
 * a top-level abstract class for most common authentication behavior is more useful as an extension point instead of
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class AuthenticatingRealm extends CachingRealm implements LogoutAware {

    /**
     * Password matcher used to determine if the provided password matches
     * the password stored in the data store.
     */
    private CredentialsMatcher credentialsMatcher = new SimpleCredentialsMatcher();

    /**
     * The class that this realm supports for authentication tokens.  This is used by the
     * default implementation of the {@link Realm#supports(org.jsecurity.authc.AuthenticationToken)} method to
     * determine whether or not the given authentication token is supported by this realm.
     */
    private Class<? extends AuthenticationToken> authenticationTokenClass = UsernamePasswordToken.class;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthenticatingRealm() {
    }

    public AuthenticatingRealm( CacheProvider cacheProvider ) {
        setCacheProvider(cacheProvider);
    }

    public AuthenticatingRealm( CredentialsMatcher matcher ) {
        setCredentialsMatcher( matcher );
    }

    public AuthenticatingRealm( CacheProvider cacheProvider, CredentialsMatcher matcher ) {
        setCacheProvider( cacheProvider );
        setCredentialsMatcher( matcher );
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Returns the <code>CredentialsMatcher</code> used during an authentication attempt to verify submitted
     * credentials with those stored in the system.
     * 
     * <p>Unless overridden by the {@link #setCredentialsMatcher setCredentialsMatcher} method, the default
     * value is a {@link org.jsecurity.authc.credential.SimpleCredentialsMatcher SimpleCredentialsMatcher} instance.
     * 
     * @return the <code>CredentialsMatcher</code> used during an authentication attempt to verify submitted
     * credentials with those stored in the system.
     */
    public CredentialsMatcher getCredentialsMatcher() {
        return credentialsMatcher;
    }

    /**
     * Sets the CrendialsMatcher used during an authentication attempt to verify submitted credentials with those
     * stored in the system.  The implementation of this matcher can be switched via configuration to
     * support any number of schemes, including plain text comparisons, hashing comparisons, and others.
     *
     * <p>Unless overridden by this method, the default value is a
     * {@link org.jsecurity.authc.credential.SimpleCredentialsMatcher} instance.
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
     * <p>If subclasses haven't already overridden the {@link Realm#supports Realm.supports(AuthenticationToken)} method,
     * they must {@link #setAuthenticationTokenClass(Class) set a new class} if they won't support
     * <tt>UsernamePasswordToken</tt> authentication token submissions.
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
     * <p>Unless overridden by this method, the default value is
     * {@link UsernamePasswordToken UsernamePasswordToken.class} to support the majority of applications.
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
     * <tt>getAuthenticationTokenClass().isAssignableFrom( token.getClass() );</tt>.  Can be overridden
     * by subclasses for more complex token checking.
     * <p>Most configurations will only need to set a different class via
     * {@link #setAuthenticationTokenClass}, as opposed to overriding this method.
     *
     * @param token the token being submitted for authentication.
     * @return true if this authentication realm can process the submitted token instance of the class, false otherwise.
     */
    public boolean supports(AuthenticationToken token) {
        return token != null && getAuthenticationTokenClass().isAssignableFrom(token.getClass());
    }

    /**
     * This method must be implemented by subclasses to retrieve account data from an
     * implementation-specific datasource (RDBMS, LDAP, etc) for the given authentication token.
     * In most data-centric systems such as an RDBMS, LDAP, file resource, etc, this means just 'pulling'
     * account data for an associated subject/user and nothing more.  But in some systems, the method
     * could actually perform EIS specific log-in logic - it is up to the Realm implementation.
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
            throw new LockedAccountException( "Account [" + account + "] is locked." );
        }
        if ( account.isCredentialsExpired() ) {
            String msg = "The credentials for account [" + account + "] are expired";
            throw new ExpiredCredentialsException( msg );
        }

        CredentialsMatcher cm = getCredentialsMatcher();
        if ( cm != null ) {
            if ( !cm.doCredentialsMatch( token, account ) ) {
                String msg = "The credentials provided for account [" + token +
                             "] did not match the expected credentials.";
                throw new IncorrectCredentialsException( msg );
            }
        } else {
            throw new AuthenticationException( "A CredentialsMatcher must be configured in order to verify " +
                    "credentials during authentication.  If you do not wish for credentials to be examined, you " +
                    "can configure an " + AllowAllCredentialsMatcher.class.getName() + " instance." );
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
        return new SimpleAuthorizingAccount(principal, credentials);
    }
}
