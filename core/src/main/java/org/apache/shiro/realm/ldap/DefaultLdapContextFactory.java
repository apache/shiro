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

import java.util.Hashtable;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>Default implementation of {@link LdapContextFactory} that can be configured or extended to
 * customize the way {@link javax.naming.ldap.LdapContext} objects are retrieved.</p>
 * <p/>
 * <p>This implementation of {@link LdapContextFactory} is used by the {@link AbstractLdapRealm} if a
 * factory is not explictly configured.</p>
 * <p/>
 * <p>Connection pooling is enabled by default on this factory, but can be disabled using the
 * {@link #usePooling} property.</p>
 *
 * @since 0.2
 * @deprecated replaced by the {@link JndiLdapContextFactory} implementation.  This implementation will be removed
 * prior to Shiro 2.0
 */
@Deprecated
public class DefaultLdapContextFactory implements LdapContextFactory {

    //TODO - complete JavaDoc

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * The Sun LDAP property used to enable connection pooling.  This is used in the default implementation
     * to enable LDAP connection pooling.
     */
    protected static final String SUN_CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    private static final Logger log = LoggerFactory.getLogger(DefaultLdapContextFactory.class);

    protected String authentication = "simple";

    protected String principalSuffix = null;

    protected String searchBase = null;

    protected String contextFactoryClassName = "com.sun.jndi.ldap.LdapCtxFactory";

    protected String url = null;

    protected String referral = "follow";

    protected String systemUsername = null;

    protected String systemPassword = null;

    private boolean usePooling = true;

    private Map<String, String> additionalEnvironment;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets the type of LDAP authentication to perform when connecting to the LDAP server.  Defaults to "simple"
     *
     * @param authentication the type of LDAP authentication to perform.
     */
    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    /**
     * A suffix appended to the username. This is typically for
     * domain names.  (e.g. "@MyDomain.local")
     *
     * @param principalSuffix the suffix.
     */
    public void setPrincipalSuffix(String principalSuffix) {
        this.principalSuffix = principalSuffix;
    }

    /**
     * The search base for the search to perform in the LDAP server.
     * (e.g. OU=OrganizationName,DC=MyDomain,DC=local )
     *
     * @param searchBase the search base.
     * @deprecated this attribute existed, but was never used in Shiro 1.x.  It will be removed prior to Shiro 2.0.
     */
    @Deprecated
    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    /**
     * The context factory to use. This defaults to the SUN LDAP JNDI implementation
     * but can be overridden to use custom LDAP factories.
     *
     * @param contextFactoryClassName the context factory that should be used.
     */
    public void setContextFactoryClassName(String contextFactoryClassName) {
        this.contextFactoryClassName = contextFactoryClassName;
    }

    /**
     * The LDAP url to connect to. (e.g. ldap://<ldapDirectoryHostname>:<port>)
     *
     * @param url the LDAP url.
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Sets the LDAP referral property.  Defaults to "follow"
     *
     * @param referral the referral property.
     */
    public void setReferral(String referral) {
        this.referral = referral;
    }

    /**
     * The system username that will be used when connecting to the LDAP server to retrieve authorization
     * information about a user.  This must be specified for LDAP authorization to work, but is not required for
     * only authentication.
     *
     * @param systemUsername the username to use when logging into the LDAP server for authorization.
     */
    public void setSystemUsername(String systemUsername) {
        this.systemUsername = systemUsername;
    }


    /**
     * The system password that will be used when connecting to the LDAP server to retrieve authorization
     * information about a user.  This must be specified for LDAP authorization to work, but is not required for
     * only authentication.
     *
     * @param systemPassword the password to use when logging into the LDAP server for authorization.
     */
    public void setSystemPassword(String systemPassword) {
        this.systemPassword = systemPassword;
    }

    /**
     * Determines whether or not LdapContext pooling is enabled for connections made using the system
     * user account.  In the default implementation, this simply
     * sets the <tt>com.sun.jndi.ldap.connect.pool</tt> property in the LDAP context environment.  If you use an
     * LDAP Context Factory that is not Sun's default implementation, you will need to override the
     * default behavior to use this setting in whatever way your underlying LDAP ContextFactory
     * supports.  By default, pooling is enabled.
     *
     * @param usePooling true to enable pooling, or false to disable it.
     */
    public void setUsePooling(boolean usePooling) {
        this.usePooling = usePooling;
    }

    /**
     * These entries are added to the environment map before initializing the LDAP context.
     *
     * @param additionalEnvironment additional environment entries to be configured on the LDAP context.
     */
    public void setAdditionalEnvironment(Map<String, String> additionalEnvironment) {
        this.additionalEnvironment = additionalEnvironment;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public LdapContext getSystemLdapContext() throws NamingException {
        return getLdapContext(systemUsername, systemPassword);
    }

    /**
     * Deprecated - use {@link #getLdapContext(Object, Object)} instead.  This will be removed before Apache Shiro 2.0.
     *
     * @param username the username to use when creating the connection.
     * @param password the password to use when creating the connection.
     * @return a {@code LdapContext} bound using the given username and password.
     * @throws javax.naming.NamingException if there is an error creating the context.
     * @deprecated the {@link #getLdapContext(Object, Object)} method should be used in all cases to ensure more than
     *             String principals and credentials can be used.  Shiro no longer calls this method - it will be
     *             removed before the 2.0 release.
     */
    @Deprecated
    public LdapContext getLdapContext(String username, String password) throws NamingException {
        if (username != null && principalSuffix != null) {
            username += principalSuffix;
        }
        return getLdapContext((Object) username, password);
    }

    public LdapContext getLdapContext(Object principal, Object credentials) throws NamingException {
        if (url == null) {
            throw new IllegalStateException("An LDAP URL must be specified of the form ldap://<hostname>:<port>");
        }

        Hashtable<String, Object> env = new Hashtable<String, Object>();

        env.put(Context.SECURITY_AUTHENTICATION, authentication);
        if (principal != null) {
            env.put(Context.SECURITY_PRINCIPAL, principal);
        }
        if (credentials!= null) {
            env.put(Context.SECURITY_CREDENTIALS, credentials);
        }
        env.put(Context.INITIAL_CONTEXT_FACTORY, contextFactoryClassName);
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.REFERRAL, referral);

        // Only pool connections for system contexts
        if (usePooling && principal != null && principal.equals(systemUsername)) {
            // Enable connection pooling
            env.put(SUN_CONNECTION_POOLING_PROPERTY, "true");
        }

        if (additionalEnvironment != null) {
            env.putAll(additionalEnvironment);
        }

        if (log.isDebugEnabled()) {
            log.debug("Initializing LDAP context using URL [" + url + "] and username [" + systemUsername + "] " +
                    "with pooling [" + (usePooling ? "enabled" : "disabled") + "]");
        }

        return new InitialLdapContext(env, null);
    }
}
