/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm.ldap;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.ldap.UnsupportedAuthenticationMechanismException;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationNotSupportedException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * An LDAP {@link org.apache.shiro.realm.Realm Realm} implementation utilizing Sun's/Oracle's
 * <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/jndi.html">JNDI API as an LDAP API</a>.  This is
 * Shiro's default implementation for supporting LDAP, as using the JNDI API has been a common approach for Java LDAP
 * support for many years.
 * <p/>
 * This realm implementation and its backing {@link JndiLdapContextFactory} should cover 99% of all Shiro-related LDAP
 * authentication and authorization needs.  However, if it does not suit your needs, you might want to look into
 * creating your own realm using an alternative, perhaps more robust, LDAP communication API, such as the
 * <a href="http://directory.apache.org/api/">Apache LDAP API</a>.
 * <h2>Authentication</h2>
 * During an authentication attempt, if the submitted {@code AuthenticationToken}'s
 * {@link org.apache.shiro.authc.AuthenticationToken#getPrincipal() principal} is a simple username, but the
 * LDAP directory expects a complete User Distinguished Name (User DN) to establish a connection, the
 * {@link #setUserDnTemplate(String) userDnTemplate} property must be configured.  If not configured,
 * the property will pass the simple username directly as the User DN, which is often incorrect in most LDAP
 * environments (maybe Microsoft ActiveDirectory being the exception).
 * <h2>Authorization</h2>
 * By default, authorization is effectively disabled due to the default
 * {@link #doGetAuthorizationInfo(org.apache.shiro.subject.PrincipalCollection)} implementation returning {@code null}.
 * If you wish to perform authorization based on an LDAP schema, you must subclass this one
 * and override that method to reflect your organization's data model.
 * <h2>Configuration</h2>
 * This class primarily provides the {@link #setUserDnTemplate(String) userDnTemplate} property to allow you to specify
 * the your LDAP server's User DN format.  Most other configuration is performed via the nested
 * {@link LdapContextFactory contextFactory} property.
 * <p/>
 * For example, defining this realm in Shiro .ini:
 * <pre>
 * [main]
 * ldapRealm = org.apache.shiro.realm.ldap.JndiLdapRealm
 * ldapRealm.userDnTemplate = uid={0},ou=users,dc=mycompany,dc=com
 * ldapRealm.contextFactory.url = ldap://ldapHost:389
 * ldapRealm.contextFactory.authenticationMechanism = DIGEST-MD5
 * ldapRealm.contextFactory.environment[some.obscure.jndi.key] = some value
 * ...
 * </pre>
 * The default {@link #setContextFactory contextFactory} instance is a {@link JndiLdapContextFactory}.  See that
 * class's JavaDoc for more information on configuring the LDAP connection as well as specifying JNDI environment
 * properties as necessary.
 *
 * @see JndiLdapContextFactory
 *
 * @since 1.1
 * @deprecated since 2.0 if favor of the {@link org.apache.shiro.realm.AccountStoreRealm} configured with an LDAP-specific {@link org.apache.shiro.account.AccountStore AccountStore}.
 */
@Deprecated
public class JndiLdapRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(JndiLdapRealm.class);

    //The zero index currently means nothing, but could be utilized in the future for other substitution techniques.
    private static final String USERDN_SUBSTITUTION_TOKEN = "{0}";

    private String userDnPrefix;
    private String userDnSuffix;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The LdapContextFactory instance used to acquire {@link javax.naming.ldap.LdapContext LdapContext}'s at runtime
     * to acquire connections to the LDAP directory to perform authentication attempts and authorizatino queries.
     */
    private LdapContextFactory contextFactory;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /**
     * Default no-argument constructor that defaults the internal {@link LdapContextFactory} instance to a
     * {@link JndiLdapContextFactory}.
     */
    public JndiLdapRealm() {
        //Credentials Matching is not necessary - the LDAP directory will do it automatically:
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        //Any Object principal and Object credentials may be passed to the LDAP provider, so accept any token:
        setAuthenticationTokenClass(AuthenticationToken.class);
        this.contextFactory = new JndiLdapContextFactory();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Returns the User DN prefix to use when building a runtime User DN value or {@code null} if no
     * {@link #getUserDnTemplate() userDnTemplate} has been configured.  If configured, this value is the text that
     * occurs before the {@link #USERDN_SUBSTITUTION_TOKEN} in the {@link #getUserDnTemplate() userDnTemplate} value.
     *
     * @return the the User DN prefix to use when building a runtime User DN value or {@code null} if no
     *         {@link #getUserDnTemplate() userDnTemplate} has been configured.
     */
    protected String getUserDnPrefix() {
        return userDnPrefix;
    }

    /**
     * Returns the User DN suffix to use when building a runtime User DN value.  or {@code null} if no
     * {@link #getUserDnTemplate() userDnTemplate} has been configured.  If configured, this value is the text that
     * occurs after the {@link #USERDN_SUBSTITUTION_TOKEN} in the {@link #getUserDnTemplate() userDnTemplate} value.
     *
     * @return the User DN suffix to use when building a runtime User DN value or {@code null} if no
     *         {@link #getUserDnTemplate() userDnTemplate} has been configured.
     */
    protected String getUserDnSuffix() {
        return userDnSuffix;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Sets the User Distinguished Name (DN) template to use when creating User DNs at runtime.  A User DN is an LDAP
     * fully-qualified unique user identifier which is required to establish a connection with the LDAP
     * directory to authenticate users and query for authorization information.
     * <h2>Usage</h2>
     * User DN formats are unique to the LDAP directory's schema, and each environment differs - you will need to
     * specify the format corresponding to your directory.  You do this by specifying the full User DN as normal, but
     * but you use a <b>{@code {0}}</b> placeholder token in the string representing the location where the
     * user's submitted principal (usually a username or uid) will be substituted at runtime.
     * <p/>
     * For example,  if your directory
     * uses an LDAP {@code uid} attribute to represent usernames, the User DN for the {@code jsmith} user may look like
     * this:
     * <p/>
     * <pre>uid=jsmith,ou=users,dc=mycompany,dc=com</pre>
     * <p/>
     * in which case you would set this property with the following template value:
     * <p/>
     * <pre>uid=<b>{0}</b>,ou=users,dc=mycompany,dc=com</pre>
     * <p/>
     * If no template is configured, the raw {@code AuthenticationToken}
     * {@link AuthenticationToken#getPrincipal() principal} will be used as the LDAP principal.  This is likely
     * incorrect as most LDAP directories expect a fully-qualified User DN as opposed to the raw uid or username.  So,
     * ensure you set this property to match your environment!
     *
     * @param template the User Distinguished Name template to use for runtime substitution
     * @throws IllegalArgumentException if the template is null, empty, or does not contain the
     *                                  {@code {0}} substitution token.
     * @see LdapContextFactory#getLdapContext(Object,Object)
     */
    public void setUserDnTemplate(String template) throws IllegalArgumentException {
        if (!StringUtils.hasText(template)) {
            String msg = "User DN template cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        int index = template.indexOf(USERDN_SUBSTITUTION_TOKEN);
        if (index < 0) {
            String msg = "User DN template must contain the '" +
                    USERDN_SUBSTITUTION_TOKEN + "' replacement token to understand where to " +
                    "insert the runtime authentication principal.";
            throw new IllegalArgumentException(msg);
        }
        String prefix = template.substring(0, index);
        String suffix = template.substring(prefix.length() + USERDN_SUBSTITUTION_TOKEN.length());
        if (log.isDebugEnabled()) {
            log.debug("Determined user DN prefix [{}] and suffix [{}]", prefix, suffix);
        }
        this.userDnPrefix = prefix;
        this.userDnSuffix = suffix;
    }

    /**
     * Returns the User Distinguished Name (DN) template to use when creating User DNs at runtime - see the
     * {@link #setUserDnTemplate(String) setUserDnTemplate} JavaDoc for a full explanation.
     *
     * @return the User Distinguished Name (DN) template to use when creating User DNs at runtime.
     */
    public String getUserDnTemplate() {
        return getUserDn(USERDN_SUBSTITUTION_TOKEN);
    }

    /**
     * Returns the LDAP User Distinguished Name (DN) to use when acquiring an
     * {@link javax.naming.ldap.LdapContext LdapContext} from the {@link LdapContextFactory}.
     * <p/>
     * If the the {@link #getUserDnTemplate() userDnTemplate} property has been set, this implementation will construct
     * the User DN by substituting the specified {@code principal} into the configured template.  If the
     * {@link #getUserDnTemplate() userDnTemplate} has not been set, the method argument will be returned directly
     * (indicating that the submitted authentication token principal <em>is</em> the User DN).
     *
     * @param principal the principal to substitute into the configured {@link #getUserDnTemplate() userDnTemplate}.
     * @return the constructed User DN to use at runtime when acquiring an {@link javax.naming.ldap.LdapContext}.
     * @throws IllegalArgumentException if the method argument is null or empty
     * @throws IllegalStateException    if the {@link #getUserDnTemplate userDnTemplate} has not been set.
     * @see LdapContextFactory#getLdapContext(Object, Object)
     */
    protected String getUserDn(String principal) throws IllegalArgumentException, IllegalStateException {
        if (!StringUtils.hasText(principal)) {
            throw new IllegalArgumentException("User principal cannot be null or empty for User DN construction.");
        }
        String prefix = getUserDnPrefix();
        String suffix = getUserDnSuffix();
        if (prefix == null && suffix == null) {
            log.debug("userDnTemplate property has not been configured, indicating the submitted " +
                    "AuthenticationToken's principal is the same as the User DN.  Returning the method argument " +
                    "as is.");
            return principal;
        }

        int prefixLength = prefix != null ? prefix.length() : 0;
        int suffixLength = suffix != null ? suffix.length() : 0;
        StringBuilder sb = new StringBuilder(prefixLength + principal.length() + suffixLength);
        if (prefixLength > 0) {
            sb.append(prefix);
        }
        sb.append(principal);
        if (suffixLength > 0) {
            sb.append(suffix);
        }
        return sb.toString();
    }

    /**
     * Sets the LdapContextFactory instance used to acquire connections to the LDAP directory during authentication
     * attempts and authorization queries.  Unless specified otherwise, the default is a {@link JndiLdapContextFactory}
     * instance.
     *
     * @param contextFactory the LdapContextFactory instance used to acquire connections to the LDAP directory during
     *                       authentication attempts and authorization queries
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void setContextFactory(LdapContextFactory contextFactory) {
        this.contextFactory = contextFactory;
    }

    /**
     * Returns the LdapContextFactory instance used to acquire connections to the LDAP directory during authentication
     * attempts and authorization queries.  Unless specified otherwise, the default is a {@link JndiLdapContextFactory}
     * instance.
     *
     * @return the LdapContextFactory instance used to acquire connections to the LDAP directory during
     *         authentication attempts and authorization queries
     */
    public LdapContextFactory getContextFactory() {
        return this.contextFactory;
    }

    /*--------------------------------------------
    |               M E T H O D S                |
    ============================================*/

    /**
     * Delegates to {@link #queryForAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken, LdapContextFactory)},
     * wrapping any {@link NamingException}s in a Shiro {@link AuthenticationException} to satisfy the parent method
     * signature.
     *
     * @param token the authentication token containing the user's principal and credentials.
     * @return the {@link AuthenticationInfo} acquired after a successful authentication attempt
     * @throws AuthenticationException if the authentication attempt fails or if a
     *                                 {@link NamingException} occurs.
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = queryForAuthenticationInfo(token, getContextFactory());
        } catch (AuthenticationNotSupportedException e) {
            String msg = "Unsupported configured authentication mechanism";
            throw new UnsupportedAuthenticationMechanismException(msg, e);
        } catch (javax.naming.AuthenticationException e) {
            throw new AuthenticationException("LDAP authentication failed.", e);
        } catch (NamingException e) {
            String msg = "LDAP naming error while attempting to authenticate user.";
            throw new AuthenticationException(msg, e);
        }

        return info;
    }


    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfo info;
        try {
            info = queryForAuthorizationInfo(principals, getContextFactory());
        } catch (NamingException e) {
            String msg = "LDAP naming error while attempting to retrieve authorization for user [" + principals + "].";
            throw new AuthorizationException(msg, e);
        }

        return info;
    }

    /**
     * Returns the principal to use when creating the LDAP connection for an authentication attempt.
     * <p/>
     * This implementation uses a heuristic: it checks to see if the specified token's
     * {@link AuthenticationToken#getPrincipal() principal} is a {@code String}, and if so,
     * {@link #getUserDn(String) converts it} from what is
     * assumed to be a raw uid or username {@code String} into a User DN {@code String}.  Almost all LDAP directories
     * expect the authentication connection to present a User DN and not an unqualified username or uid.
     * <p/>
     * If the token's {@code principal} is not a String, it is assumed to already be in the format supported by the
     * underlying {@link LdapContextFactory} implementation and the raw principal is returned directly.
     *
     * @param token the {@link AuthenticationToken} submitted during the authentication process
     * @return the User DN or raw principal to use to acquire the LdapContext.
     * @see LdapContextFactory#getLdapContext(Object, Object)
     */
    protected Object getLdapPrincipal(AuthenticationToken token) {
        Object principal = token.getPrincipal();
        if (principal instanceof String) {
            String sPrincipal = (String) principal;
            return getUserDn(sPrincipal);
        }
        return principal;
    }

    /**
     * This implementation opens an LDAP connection using the token's
     * {@link #getLdapPrincipal(org.apache.shiro.authc.AuthenticationToken) discovered principal} and provided
     * {@link AuthenticationToken#getCredentials() credentials}.  If the connection opens successfully, the
     * authentication attempt is immediately considered successful and a new
     * {@link AuthenticationInfo} instance is
     * {@link #createAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken, Object, Object, javax.naming.ldap.LdapContext) created}
     * and returned.  If the connection cannot be opened, either because LDAP authentication failed or some other
     * JNDI problem, an {@link NamingException} will be thrown.
     *
     * @param token              the submitted authentication token that triggered the authentication attempt.
     * @param ldapContextFactory factory used to retrieve LDAP connections.
     * @return an {@link AuthenticationInfo} instance representing the authenticated user's information.
     * @throws NamingException if any LDAP errors occur.
     */
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token,
                                                            LdapContextFactory ldapContextFactory)
            throws NamingException {

        Object principal = token.getPrincipal();
        Object credentials = token.getCredentials();

        log.debug("Authenticating user '{}' through LDAP", principal);

        principal = getLdapPrincipal(token);

        LdapContext ctx = null;
        try {
            ctx = ldapContextFactory.getLdapContext(principal, credentials);
            //context was opened successfully, which means their credentials were valid.  Return the AuthenticationInfo:
            return createAuthenticationInfo(token, principal, credentials, ctx);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    /**
     * Returns the {@link AuthenticationInfo} resulting from a Subject's successful LDAP authentication attempt.
     * <p/>
     * This implementation ignores the {@code ldapPrincipal}, {@code ldapCredentials}, and the opened
     * {@code ldapContext} arguments and merely returns an {@code AuthenticationInfo} instance mirroring the
     * submitted token's principal and credentials.  This is acceptable because this method is only ever invoked after
     * a successful authentication attempt, which means the provided principal and credentials were correct, and can
     * be used directly to populate the (now verified) {@code AuthenticationInfo}.
     * <p/>
     * Subclasses however are free to override this method for more advanced construction logic.
     *
     * @param token           the submitted {@code AuthenticationToken} that resulted in a successful authentication
     * @param ldapPrincipal   the LDAP principal used when creating the LDAP connection.  Unlike the token's
     *                        {@link AuthenticationToken#getPrincipal() principal}, this value is usually a constructed
     *                        User DN and not a simple username or uid.  The exact value is depending on the
     *                        configured
     *                        <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html">
     *                        LDAP authentication mechanism</a> in use.
     * @param ldapCredentials the LDAP credentials used when creating the LDAP connection.
     * @param ldapContext     the LdapContext created that resulted in a successful authentication.  It can be used
     *                        further by subclasses for more complex operations.  It does not need to be closed -
     *                        it will be closed automatically after this method returns.
     * @return the {@link AuthenticationInfo} resulting from a Subject's successful LDAP authentication attempt.
     * @throws NamingException if there was any problem using the {@code LdapContext}
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected AuthenticationInfo createAuthenticationInfo(AuthenticationToken token, Object ldapPrincipal,
                                                          Object ldapCredentials, LdapContext ldapContext)
            throws NamingException {
        return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }


    /**
     * Method that should be implemented by subclasses to build an
     * {@link AuthorizationInfo} object by querying the LDAP context for the
     * specified principal.</p>
     *
     * @param principals          the principals of the Subject whose AuthenticationInfo should be queried from the LDAP server.
     * @param ldapContextFactory factory used to retrieve LDAP connections.
     * @return an {@link AuthorizationInfo} instance containing information retrieved from the LDAP server.
     * @throws NamingException if any LDAP errors occur during the search.
     */
    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals,
                                                          LdapContextFactory ldapContextFactory) throws NamingException {
        return null;
    }
}
