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

import org.apache.shiro.lang.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * {@link LdapContextFactory} implementation using the default Sun/Oracle JNDI Ldap API, utilizing JNDI
 * environment properties and an {@link javax.naming.InitialContext}.
 * <h2>Configuration</h2>
 * This class basically wraps a default template JNDI environment properties Map.  This properties map is the base
 * configuration template used to acquire JNDI {@link LdapContext} connections at runtime.  The
 * {@link #getLdapContext(Object, Object)} method implementation merges this default template with other properties
 * accessible at runtime only (for example per-method principals and credentials).  The constructed runtime map is the
 * one used to acquire the {@link LdapContext}.
 * <p/>
 * The template can be configured directly via the {@link #getEnvironment()}/{@link #setEnvironment(java.util.Map)}
 * properties directly if necessary, but it is usually more convenient to use the supporting wrapper get/set methods
 * for various environment properties.  These wrapper methods interact with the environment
 * template on your behalf, leaving your configuration cleaner and easier to understand.
 * <p/>
 * For example, consider the following two identical configurations:
 * <pre>
 * [main]
 * ldapRealm = org.apache.shiro.realm.ldap.DefaultLdapRealm
 * ldapRealm.contextFactory.url = ldap://localhost:389
 * ldapRealm.contextFactory.authenticationMechanism = DIGEST-MD5
 * </pre>
 * and
 * <pre>
 * [main]
 * ldapRealm = org.apache.shiro.realm.ldap.DefaultLdapRealm
 * ldapRealm.contextFactory.environment[java.naming.provider.url] = ldap://localhost:389
 * ldapRealm.contextFactory.environment[java.naming.security.authentication] = DIGEST-MD5
 * </pre>
 * As you can see, the 2nd configuration block is a little more difficult to read and also requires knowledge
 * of the underlying JNDI Context property keys.  The first is easier to read and understand.
 * <p/>
 * Note that occasionally it will be necessary to use the latter configuration style to set environment properties
 * where no corresponding wrapper method exists.  In this case, the hybrid approach is still a little easier to read.
 * For example:
 * <pre>
 * [main]
 * ldapRealm = org.apache.shiro.realm.ldap.DefaultLdapRealm
 * ldapRealm.contextFactory.url = ldap://localhost:389
 * ldapRealm.contextFactory.authenticationMechanism = DIGEST-MD5
 * ldapRealm.contextFactory.environment[some.other.obscure.jndi.key] = some value
 * </pre>
 *
 * @since 1.1
 */
public class JndiLdapContextFactory implements LdapContextFactory {

    /*-------------------------------------------
     |             C O N S T A N T S            |
     ===========================================*/
    /**
     * The Sun LDAP property used to enable connection pooling.  This is used in the default implementation
     * to enable LDAP connection pooling.
     */
    protected static final String SUN_CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";
    protected static final String DEFAULT_CONTEXT_FACTORY_CLASS_NAME = "com.sun.jndi.ldap.LdapCtxFactory";
    protected static final String SIMPLE_AUTHENTICATION_MECHANISM_NAME = "simple";
    protected static final String DEFAULT_REFERRAL = "follow";

    private static final Logger LOGGER = LoggerFactory.getLogger(JndiLdapContextFactory.class);

    /*-------------------------------------------
     |    I N S T A N C E   V A R I A B L E S   |
     ============================================*/
    private Map<String, Object> environment;
    private boolean poolingEnabled;
    private String systemPassword;
    private String systemUsername;

    /*-------------------------------------------
     |         C O N S T R U C T O R S          |
     ===========================================*/

    /**
     * Default no-argument constructor that initializes the backing {@link #getEnvironment() environment template} with
     * the {@link #setContextFactoryClassName(String) contextFactoryClassName} equal to
     * {@code com.sun.jndi.ldap.LdapCtxFactory} (the Sun/Oracle default) and the default
     * {@link #setReferral(String) referral} behavior to {@code follow}.
     */
    public JndiLdapContextFactory() {
        this.environment = new HashMap<String, Object>();
        setContextFactoryClassName(DEFAULT_CONTEXT_FACTORY_CLASS_NAME);
        setReferral(DEFAULT_REFERRAL);
        poolingEnabled = true;
    }

    /*-------------------------------------------
     |  A C C E S S O R S / M O D I F I E R S   |
     ===========================================*/

    /**
     * Sets the type of LDAP authentication mechanism to use when connecting to the LDAP server.
     * This is a wrapper method for setting the JNDI {@link #getEnvironment() environment template}'s
     * {@link Context#SECURITY_AUTHENTICATION} property.
     * <p/>
     * "none" (i.e. anonymous) and "simple" authentications are supported automatically and don't need to be configured
     * via this property.  However, if you require a different mechanism, such as a SASL or External mechanism, you
     * must configure that explicitly via this property.  See the
     * <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html">JNDI LDAP
     * Authentication Mechanisms</a> for more information.
     *
     * @param authenticationMechanism the type of LDAP authentication to perform.
     * @see <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html">
     * http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html</a>
     */
    public void setAuthenticationMechanism(String authenticationMechanism) {
        setEnvironmentProperty(Context.SECURITY_AUTHENTICATION, authenticationMechanism);
    }

    /**
     * Returns the type of LDAP authentication mechanism to use when connecting to the LDAP server.
     * This is a wrapper method for getting the JNDI {@link #getEnvironment() environment template}'s
     * {@link Context#SECURITY_AUTHENTICATION} property.
     * <p/>
     * If this property remains un-configured (i.e. {@code null} indicating the
     * {@link #setAuthenticationMechanism(String)} method wasn't used), this indicates that the default JNDI
     * "none" (anonymous) and "simple" authentications are supported automatically.  Any non-null value returned
     * represents an explicitly configured mechanism (e.g. a SASL or external mechanism). See the
     * <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html">JNDI LDAP
     * Authentication Mechanisms</a> for more information.
     *
     * @return the type of LDAP authentication mechanism to use when connecting to the LDAP server.
     * @see <a href="http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html">
     * http://download-llnw.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html</a>
     */
    public String getAuthenticationMechanism() {
        return (String) getEnvironmentProperty(Context.SECURITY_AUTHENTICATION);
    }

    /**
     * The name of the ContextFactory class to use. This defaults to the SUN LDAP JNDI implementation
     * but can be overridden to use custom LDAP factories.
     * <p/>
     * This is a wrapper method for setting the JNDI environment's {@link Context#INITIAL_CONTEXT_FACTORY} property.
     *
     * @param contextFactoryClassName the context factory that should be used.
     */
    public void setContextFactoryClassName(String contextFactoryClassName) {
        setEnvironmentProperty(Context.INITIAL_CONTEXT_FACTORY, contextFactoryClassName);
    }

    /**
     * Sets the name of the ContextFactory class to use. This defaults to the SUN LDAP JNDI implementation
     * but can be overridden to use custom LDAP factories.
     * <p/>
     * This is a wrapper method for getting the JNDI environment's {@link Context#INITIAL_CONTEXT_FACTORY} property.
     *
     * @return the name of the ContextFactory class to use.
     */
    public String getContextFactoryClassName() {
        return (String) getEnvironmentProperty(Context.INITIAL_CONTEXT_FACTORY);
    }

    /**
     * Returns the base JNDI environment template to use when acquiring an LDAP connection (an {@link LdapContext}).
     * This property is the base configuration template to use for all connections.  This template is then
     * merged with appropriate runtime values as necessary in the
     * {@link #getLdapContext(Object, Object)} implementation.  The merged environment instance is what is used to
     * acquire the {@link LdapContext} at runtime.
     * <p/>
     * Most other get/set methods in this class act as thin proxy wrappers that interact with this property.  The
     * benefit of using them is you have an easier-to-use configuration mechanism compared to setting map properties
     * based on JNDI context keys.
     *
     * @return the base JNDI environment template to use when acquiring an LDAP connection (an {@link LdapContext})
     */
    public Map getEnvironment() {
        return this.environment;
    }

    /**
     * Sets the base JNDI environment template to use when acquiring LDAP connections.  It is typically more common
     * to use the other get/set methods in this class to set individual environment settings rather than use
     * this method, but it is available for advanced users that want full control over the base JNDI environment
     * settings.
     * <p/>
     * Note that this template only represents the base/default environment settings.  It is then merged with
     * appropriate runtime values as necessary in the {@link #getLdapContext(Object, Object)} implementation.
     * The merged environment instance is what is used to acquire the connection ({@link LdapContext}) at runtime.
     *
     * @param env the base JNDI environment template to use when acquiring LDAP connections.
     */
    @SuppressWarnings({"unchecked"})
    public void setEnvironment(Map env) {
        this.environment = env;
    }

    /**
     * Returns the environment property value bound under the specified key.
     *
     * @param name the name of the environment property
     * @return the property value or {@code null} if the value has not been set.
     */
    private Object getEnvironmentProperty(String name) {
        return this.environment.get(name);
    }

    /**
     * Will apply the value to the environment attribute if and only if the value is not null or empty.  If it is
     * null or empty, the corresponding environment attribute will be removed.
     *
     * @param name  the environment property key
     * @param value the environment property value.  A null/empty value will trigger removal.
     */
    private void setEnvironmentProperty(String name, String value) {
        if (StringUtils.hasText(value)) {
            this.environment.put(name, value);
        } else {
            this.environment.remove(name);
        }
    }

    /**
     * Returns whether or not connection pooling should be used when possible and appropriate.  This property is NOT
     * backed by the {@link #getEnvironment() environment template} like most other properties in this class.  It
     * is a flag to indicate that pooling is preferred.  The default value is {@code true}.
     * <p/>
     * However, pooling will only actually be enabled if this property is {@code true} <em>and</em> the connection
     * being created is for the {@link #getSystemUsername() systemUsername} user.  Connection pooling is not used for
     * general authentication attempts by application end-users because the probability of re-use for that same
     * user-specific connection after an authentication attempt is extremely low.
     * <p/>
     * If this attribute is {@code true} and it has been determined that the connection is being made with the
     * {@link #getSystemUsername() systemUsername}, the
     * {@link #getLdapContext(Object, Object)} implementation will set the Sun/Oracle-specific
     * {@code com.sun.jndi.ldap.connect.pool} environment property to &quot;{@code true}&quot;.  This means setting
     * this property is only likely to work if using the Sun/Oracle default context factory class (i.e. not using
     * a custom {@link #getContextFactoryClassName() contextFactoryClassName}).
     *
     * @return whether or not connection pooling should be used when possible and appropriate
     */
    public boolean isPoolingEnabled() {
        return poolingEnabled;
    }

    /**
     * Sets whether or not connection pooling should be used when possible and appropriate.  This property is NOT
     * a wrapper to the {@link #getEnvironment() environment template} like most other properties in this class.  It
     * is a flag to indicate that pooling is preferred.  The default value is {@code true}.
     * <p/>
     * However, pooling will only actually be enabled if this property is {@code true} <em>and</em> the connection
     * being created is for the {@link #getSystemUsername() systemUsername} user.  Connection pooling is not used for
     * general authentication attempts by application end-users because the probability of re-use for that same
     * user-specific connection after an authentication attempt is extremely low.
     * <p/>
     * If this attribute is {@code true} and it has been determined that the connection is being made with the
     * {@link #getSystemUsername() systemUsername}, the
     * {@link #getLdapContext(Object, Object)} implementation will set the Sun/Oracle-specific
     * {@code com.sun.jndi.ldap.connect.pool} environment property to &quot;{@code true}&quot;.  This means setting
     * this property is only likely to work if using the Sun/Oracle default context factory class (i.e. not using
     * a custom {@link #getContextFactoryClassName() contextFactoryClassName}).
     *
     * @param poolingEnabled whether or not connection pooling should be used when possible and appropriate
     */
    public void setPoolingEnabled(boolean poolingEnabled) {
        this.poolingEnabled = poolingEnabled;
    }

    /**
     * Sets the LDAP referral behavior when creating a connection.  Defaults to {@code follow}.  See the Sun/Oracle LDAP
     * <a href="http://java.sun.com/products/jndi/tutorial/ldap/referral/jndi.html">referral documentation</a> for more.
     *
     * @param referral the referral property.
     * @see <a href="http://java.sun.com/products/jndi/tutorial/ldap/referral/jndi.html">Referrals in JNDI</a>
     */
    public void setReferral(String referral) {
        setEnvironmentProperty(Context.REFERRAL, referral);
    }

    /**
     * Returns the LDAP referral behavior when creating a connection.  Defaults to {@code follow}.
     * See the Sun/Oracle LDAP
     * <a href="http://java.sun.com/products/jndi/tutorial/ldap/referral/jndi.html">referral documentation</a> for more.
     *
     * @return the LDAP referral behavior when creating a connection.
     * @see <a href="http://java.sun.com/products/jndi/tutorial/ldap/referral/jndi.html">Referrals in JNDI</a>
     */
    public String getReferral() {
        return (String) getEnvironmentProperty(Context.REFERRAL);
    }

    /**
     * The LDAP url to connect to. (e.g. ldap://&lt;ldapDirectoryHostname&gt;:&lt;port&gt;).  This must be configured.
     *
     * @param url the LDAP url to connect to. (e.g. ldap://&lt;ldapDirectoryHostname&gt;:&lt;port&gt;)
     */
    public void setUrl(String url) {
        setEnvironmentProperty(Context.PROVIDER_URL, url);
    }

    /**
     * Returns the LDAP url to connect to. (e.g. ldap://&lt;ldapDirectoryHostname&gt;:&lt;port&gt;).
     * This must be configured.
     *
     * @return the LDAP url to connect to. (e.g. ldap://&lt;ldapDirectoryHostname&gt;:&lt;port&gt;)
     */
    public String getUrl() {
        return (String) getEnvironmentProperty(Context.PROVIDER_URL);
    }

    /**
     * Sets the password of the {@link #setSystemUsername(String) systemUsername} that will be used when creating an
     * LDAP connection used for authorization queries.
     * <p/>
     * Note that setting this property is not required if the calling LDAP Realm does not perform authorization
     * checks.
     *
     * @param systemPassword the password of the {@link #setSystemUsername(String) systemUsername} that will be used
     *                       when creating an LDAP connection used for authorization queries.
     */
    public void setSystemPassword(String systemPassword) {
        this.systemPassword = systemPassword;
    }

    /**
     * Returns the password of the {@link #setSystemUsername(String) systemUsername} that will be used when creating an
     * LDAP connection used for authorization queries.
     * <p/>
     * Note that setting this property is not required if the calling LDAP Realm does not perform authorization
     * checks.
     *
     * @return the password of the {@link #setSystemUsername(String) systemUsername} that will be used when creating an
     * LDAP connection used for authorization queries.
     */
    public String getSystemPassword() {
        return this.systemPassword;
    }

    /**
     * Sets the system username that will be used when creating an LDAP connection used for authorization queries.
     * The user must have the ability to query for authorization data for any application user.
     * <p/>
     * Note that setting this property is not required if the calling LDAP Realm does not perform authorization
     * checks.
     *
     * @param systemUsername the system username that will be used when creating an LDAP connection used for
     *                       authorization queries.
     */
    public void setSystemUsername(String systemUsername) {
        this.systemUsername = systemUsername;
    }

    /**
     * Returns the system username that will be used when creating an LDAP connection used for authorization queries.
     * The user must have the ability to query for authorization data for any application user.
     * <p/>
     * Note that setting this property is not required if the calling LDAP Realm does not perform authorization
     * checks.
     *
     * @return the system username that will be used when creating an LDAP connection used for authorization queries.
     */
    public String getSystemUsername() {
        return systemUsername;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * This implementation delegates to {@link #getLdapContext(Object, Object)} using the
     * {@link #getSystemUsername() systemUsername} and {@link #getSystemPassword() systemPassword} properties as
     * arguments.
     *
     * @return the system LdapContext
     * @throws NamingException if there is a problem connecting to the LDAP directory
     */
    public LdapContext getSystemLdapContext() throws NamingException {
        return getLdapContext(getSystemUsername(), getSystemPassword());
    }

    /**
     * Returns {@code true} if LDAP connection pooling should be used when acquiring a connection based on the specified
     * account principal, {@code false} otherwise.
     * <p/>
     * This implementation returns {@code true} only if {@link #isPoolingEnabled()} and the principal equals the
     * {@link #getSystemUsername()}.  The reasoning behind this is that connection pooling is not desirable for
     * general authentication attempts by application end-users because the probability of re-use for that same
     * user-specific connection after an authentication attempt is extremely low.
     *
     * @param principal the principal under which the connection will be made
     * @return {@code true} if LDAP connection pooling should be used when acquiring a connection based on the specified
     * account principal, {@code false} otherwise.
     */
    protected boolean isPoolingConnections(Object principal) {
        return isPoolingEnabled() && principal != null && principal.equals(getSystemUsername());
    }

    /**
     * This implementation returns an LdapContext based on the configured JNDI/LDAP environment configuration.
     * The environment (Map) used at runtime is created by merging the default/configured
     * {@link #getEnvironment() environment template} with some runtime values as necessary (e.g. a principal and
     * credential available at runtime only).
     * <p/>
     * After the merged Map instance is created, the LdapContext connection is
     * {@link #createLdapContext(java.util.Hashtable) created} and returned.
     *
     * @param principal   the principal to use when acquiring a connection to the LDAP directory
     * @param credentials the credentials (password, X.509 certificate, etc.) to use when acquiring a connection to the
     *                    LDAP directory
     * @return the acquired {@code LdapContext} connection bound using the specified principal and credentials.
     * @throws NamingException
     * @throws IllegalStateException
     */
    public LdapContext getLdapContext(Object principal, Object credentials) throws NamingException,
            IllegalStateException {

        String url = getUrl();
        if (url == null) {
            throw new IllegalStateException("An LDAP URL must be specified of the form ldap://<hostname>:<port>");
        }

        //copy the environment template into the runtime instance that will be further edited based on
        //the method arguments and other class attributes.
        Hashtable<String, Object> env = new Hashtable<String, Object>(this.environment);

        Object authcMech = getAuthenticationMechanism();
        if (authcMech == null && (principal != null || credentials != null)) {
            //authenticationMechanism has not been set, but either a principal and/or credentials were
            //supplied, indicating that at least a 'simple' authentication attempt is indeed occurring - the Shiro
            //end-user just didn't configure it explicitly.  So we set it to be 'simple' here as a convenience;
            //the Sun provider implementation already does this same logic, but by repeating that logic here, we ensure
            //this convenience exists regardless of provider implementation):
            env.put(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION_MECHANISM_NAME);
        }
        if (principal != null) {
            env.put(Context.SECURITY_PRINCIPAL, principal);
        }
        if (credentials != null) {
            env.put(Context.SECURITY_CREDENTIALS, credentials);
        }

        boolean pooling = isPoolingConnections(principal);
        if (pooling) {
            env.put(SUN_CONNECTION_POOLING_PROPERTY, "true");
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Initializing LDAP context using URL [{}] and principal [{}] with pooling {}",
                    new Object[] {url, principal, (pooling ? "enabled" : "disabled")});
        }

        // validate the config before creating the context
        validateAuthenticationInfo(env);

        return createLdapContext(env);
    }

    /**
     * Creates and returns a new {@link javax.naming.ldap.InitialLdapContext} instance.  This method exists primarily
     * to support testing where a mock LdapContext can be returned instead of actually creating a connection, but
     * subclasses are free to provide a different implementation if necessary.
     *
     * @param env the JNDI environment settings used to create the LDAP connection
     * @return an LdapConnection
     * @throws NamingException if a problem occurs creating the connection
     */
    protected LdapContext createLdapContext(Hashtable env) throws NamingException {
        return new InitialLdapContext(env, null);
    }


    /**
     * Validates the configuration in the JNDI <code>environment</code> settings and throws an exception if a problem
     * exists.
     * <p/>
     * This implementation will throw a {@link AuthenticationException} if the authentication mechanism is set to
     * 'simple', the principal is non-empty, and the credentials are empty (as per
     * <a href="http://tools.ietf.org/html/rfc4513#section-5.1.2">rfc4513 section-5.1.2</a>).
     *
     * @param environment the JNDI environment settings to be validated
     * @throws AuthenticationException if a configuration problem is detected
     */
    protected void validateAuthenticationInfo(Hashtable<String, Object> environment)
            throws AuthenticationException {
        // validate when using Simple auth both principal and credentials are set
        if (SIMPLE_AUTHENTICATION_MECHANISM_NAME.equals(environment.get(Context.SECURITY_AUTHENTICATION))) {

            // only validate credentials if we have a non-empty principal
            if (environment.get(Context.SECURITY_PRINCIPAL) != null
                    && StringUtils.hasText(String.valueOf(environment.get(Context.SECURITY_PRINCIPAL)))) {

                Object credentials = environment.get(Context.SECURITY_CREDENTIALS);

                // from the FAQ, we need to check for empty credentials:
                // http://docs.oracle.com/javase/tutorial/jndi/ldap/faq.html
                if (credentials == null
                        || (credentials instanceof byte[] && ((byte[]) credentials).length <= 0)
                        || (credentials instanceof char[] && ((char[]) credentials).length <= 0)
                        || (String.class.isInstance(credentials) && !StringUtils.hasText(String.valueOf(credentials)))) {

                    throw new javax.naming.AuthenticationException("LDAP Simple authentication requires both a "
                            + "principal and credentials.");
                }
            }
        }
    }

}
