/*
 * Copyright (C) 2005-2007 Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.realm.support.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;
import java.util.Map;

/**
 * <p>Default implementation of {@link LdapContextFactory} that can be configured or extended to
 * customize the way {@link javax.naming.ldap.LdapContext} objects are retrieved.</p>
 *
 * <p>This implementation of {@link LdapContextFactory} is used by the {@link AbstractLdapRealm} if a
 * factory is not explictly configured.</p>
 *
 * <p>Connection pooling is enabled by default on this factory, but can be disabled using the
 * {@link #usePooling} property.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class DefaultLdapContextFactory implements LdapContextFactory {

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

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected String authentication = "simple";

    protected String principalSuffix = null;

    protected String searchBase = null;

    protected String contextFactoryClassName = "com.sun.jndi.ldap.LdapCtxFactory";

    protected String url = null;

    protected String referral = "follow";

    protected String systemUsername = null;

    protected String systemPassword = null;

    private boolean usePooling = true;

    private Map<String,String> additionalEnvironment;

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
    public void setAuthentication( String authentication ) {
        this.authentication = authentication;
    }

    /**
     * A suffix appended to the username. This is typically for
     * domain names.  (e.g. "@MyDomain.local")
     *
     * @param principalSuffix the suffix.
     */
    public void setPrincipalSuffix( String principalSuffix ) {
        this.principalSuffix = principalSuffix;
    }

    /**
     * The search base for the search to perform in the LDAP server.
     * (e.g. OU=OrganizationName,DC=MyDomain,DC=local )
     *
     * @param searchBase the search base.
     */
    public void setSearchBase( String searchBase ) {
        this.searchBase = searchBase;
    }

    /**
     * The context factory to use. This defaults to the SUN LDAP JNDI implementation
     * but can be overridden to use custom LDAP factories.
     *
     * @param contextFactoryClassName the context factory that should be used.
     */
    public void setContextFactoryClassName( String contextFactoryClassName ) {
        this.contextFactoryClassName = contextFactoryClassName;
    }

    /**
     * The LDAP url to connect to. (e.g. ldap://<ldapDirectoryHostname>:<port>)
     *
     * @param url the LDAP url.
     */
    public void setUrl( String url ) {
        this.url = url;
    }

    /**
     * Sets the LDAP referral property.  Defaults to "follow"
     *
     * @param referral the referral property.
     */
    public void setReferral( String referral ) {
        this.referral = referral;
    }

    /**
     * The system username that will be used when connecting to the LDAP server to retrieve authorization
     * information about a user.  This must be specified for LDAP authorization to work, but is not required for
     * only authentication.
     *
     * @param systemUsername the username to use when logging into the LDAP server for authorization.
     */
    public void setSystemUsername( String systemUsername ) {
        this.systemUsername = systemUsername;
    }


    /**
     * The system password that will be used when connecting to the LDAP server to retrieve authorization
     * information about a user.  This must be specified for LDAP authorization to work, but is not required for
     * only authentication.
     *
     * @param systemPassword the password to use when logging into the LDAP server for authorization.
     */
    public void setSystemPassword( String systemPassword ) {
        this.systemPassword = systemPassword;
    }

    /**
     * Determines whether or not LdapContext pooling is enabled for connections made using the system
     * user account.  In the default implementation, this simply
     * sets the <tt>com.sun.jndi.ldap.connect.pool</tt> property in the LDAP context environment.  If you use an
     * LDAP Context Factory that is not Sun's default implementation, you will need to override the
     * default behavior to use this setting in whatever way your underlying LDAP ContextFactory
     * supports.  By default, pooling is enabled.
     * @param usePooling true to enable pooling, or false to disable it.
     */
    public void setUsePooling(boolean usePooling) {
        this.usePooling = usePooling;
    }

    /**
     * These entries are added to the environment map before initializing the LDAP context.
     * @param additionalEnvironment additional environment entries to be configured on the LDAP context.
     */
    public void setAdditionalEnvironment(Map<String, String> additionalEnvironment) {
        this.additionalEnvironment = additionalEnvironment;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public LdapContext getSystemLdapContext() throws NamingException {
        return getLdapContext( systemUsername, systemPassword );
    }

    public LdapContext getLdapContext(String username, String password) throws NamingException {
        if ( searchBase == null ) {
            throw new IllegalStateException( "A search base must be specified." );
        }
        if ( url == null ) {
            throw new IllegalStateException( "An LDAP URL must be specified of the form ldap://<hostname>:<port>" );
        }

        if( principalSuffix != null ) {
            username += principalSuffix;
        }

        Hashtable<String, String> env = new Hashtable<String, String>();

        env.put( Context.SECURITY_AUTHENTICATION, authentication );
        env.put( Context.SECURITY_PRINCIPAL, username );
        env.put( Context.SECURITY_CREDENTIALS, password );
        env.put( Context.INITIAL_CONTEXT_FACTORY, contextFactoryClassName);
        env.put( Context.PROVIDER_URL, url );
        env.put( Context.REFERRAL, referral );

        // Only pool connections for system contexts
        if( usePooling && username.equals( systemUsername )) {
            // Enable connection pooling
            env.put(SUN_CONNECTION_POOLING_PROPERTY, "true");
        }

        if( additionalEnvironment != null ) {
            env.putAll( additionalEnvironment );
        }

        if ( log.isDebugEnabled() ) {
            log.debug( "Initializing LDAP context using URL [" + url + "] and username [" + systemUsername + "] " +
                    "with pooling [" + (usePooling ? "enabled" : "disabled") + "]" );
        }

        return new InitialLdapContext( env, null );
    }
}
