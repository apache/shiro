/*
* Copyright (C) 2005 Jeremy C. Haile
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

package org.jsecurity.ri;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.Configuration;
import org.jsecurity.cache.CacheException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.context.SecurityContextException;
import org.jsecurity.context.SecurityContext;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.Properties;

/**
 * Default implementation of the configuration interface for the JSecurity
 * Reference Implementation.  Properties can be configured programmatically or specified via a
 * Properties collection.  If properties are specified via a properties collection, they will be
 * loaded from a <tt>jsecurity.properties</tt> file (unless otherwise specified.  System properties
 * can also override the properties specified in the JSecurity properties file.
 *
 * todo This needs to be moved back into the RI module, but is here temporarily until the SecurityContext can be modified to not create its own configuration, but get it from the security manager. -JCH 5/29/06
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class DefaultConfiguration implements Configuration {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * Name of the JSecurity properties file to be loaded.  This file should contain properties
     * telling JSecurity how to create a security context.
     */
    private static final String JSECURITY_PROPS_FILE = "jsecurity.properties";


    /**
     * Name of the system property or file property that determines the class name of the {@link
     * SecurityContext} implementation class to use.
     */
    private static final String SECURITY_CONTEXT_CLASS_NAME_PROP = "securityContext.class.name";

    /**
     * <p>This property determines whether or not the security context implementation should be
     * cached. The JSecurity implementation is responsible for configuring whether or not caching of
     * the implementation is allowed.  The default value of this property is true for performance
     * reasons, although implementations are allowed to override the value either through
     * the properties file or a system property.</p>
     * <p>This property should be set to &quot;false&quot; to disable caching of the implementation.
     * Any other value will leave caching enabled.</p>
     */
    private static final String SECURITY_CONTEXT_CACHED_PROP = "securityContext.cached";

    /**
     * The class name of the cache provider to use for this JSecurity deployment,
     * This class should implement the {@link CacheProvider} interface.
     * The default value of this is <tt>org.jsecurity.ri.cache.support.EhCacheProvider</tt>
     */
    public static final String CACHE_PROVIDER_CLASS_NAME_PROP = "security.cache.provider.class";

    /**
     * Whether or not authorization information should be cached by realms in this deployment.
     * This property should be set to "troe" to enable authorization information caching
     * (for dynamic authorization configurations)  Any other value will enable authorization
     * caching.  The default value of this is <tt>true</tt>.
     */
    public static final String CACHE_AUTHORIZATION_INFO_PROP = "security.cache.authorization";

    /**
     * The default class name of the security context implementation that should be used.
     */
    private static final String DEFAULT_SECURITY_CONTEXT_CLASS_NAME = "org.jsecurity.ri.context.ThreadLocalSecurityContext";

    /**
     * The default cache provider class name that should be used if one is not specified in the configuration.
     */
    private static final String DEFAULT_CACHE_PROVIDER_CLASS_NAME = "org.jsecurity.ri.cache.support.EhCacheProvider";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The class name of the class used to access the security context information.
     */
    private String securityContextClassName = DEFAULT_SECURITY_CONTEXT_CLASS_NAME;

    /**
     * True if the security context implementation can be statically cached, or false otherwise.
     */
    private boolean securityContextCached = true;

    /**
     * The class name of the default cache provider to use for this JSecurity deployment.
     */
    private String cacheProviderClassName = DEFAULT_CACHE_PROVIDER_CLASS_NAME;

    /**
     * True if authorization information should be cached in realms by default.
     */
    private boolean cacheAuthorizationInfo = true;

    /**
     * The default cache provider associated with this configuration.
     */
    private CacheProvider defaultCacheProvider;

    /**
     * The set of properties associated with this configuration.  This may include implementation-specific
     * properties and so are maintained separately from the standard properties that are parsed into
     * instance variables.
     */
    private Properties properties;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public DefaultConfiguration() {
        this( true );
    }

    public DefaultConfiguration( boolean loadFromClassPath ) {
        this( JSECURITY_PROPS_FILE, loadFromClassPath );
    }

    public DefaultConfiguration( String filename, boolean loadFromClassPath ) {
        this( getJSecurityProperties( filename, loadFromClassPath ) );
    }


    private static Properties getJSecurityProperties(String filename, boolean loadFromClassPath) {

        InputStream propsFileIs = null;
        if( loadFromClassPath ) {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            if ( cl == null ) {
                cl = DefaultConfiguration.class.getClassLoader();
            }
            propsFileIs = cl.getResourceAsStream( filename );
        } else {
            try {
                propsFileIs = new FileInputStream( filename );
            } catch (FileNotFoundException e) {
                throw new SecurityContextException( "JSecurity properties file [" + filename + "] " +
                    "could not be loaded from the file system.", e );
            }
        }

        Properties props = new Properties();
        try {
            props.load( propsFileIs );
        } catch ( IOException e ) {
            String msg = "No [" + SECURITY_CONTEXT_CLASS_NAME_PROP + "] system property " +
                         "is defined and [" + JSECURITY_PROPS_FILE + "] cannot be " +
                         "loaded from the classloader or as a file.  A " +
                         SecurityContext.class.getName() + "cannot be created.";
            throw new SecurityContextException( msg );
        }
        return props;
    }


    public DefaultConfiguration( Properties props ) {
        setProperties( props );

        String implClassName = getStringProperty( props, SECURITY_CONTEXT_CLASS_NAME_PROP, null );
        if ( implClassName == null || implClassName.length() == 0 ) {
            String msg = "No [" + SecurityContext.class.getName() + "] implementation " +
                         "class was found configured in the system.  The " +
                         "implementation should normally be specified by including the " +
                         "JSecurity implementation JAR in the classpath.  The implementation can " +
                         "also be specified by setting the [" + SECURITY_CONTEXT_CLASS_NAME_PROP +
                         "] system property or manually including that value in a " +
                         "jsecurity.properties file at the root of the classpath.";
            throw new SecurityContextException( msg );
        }
        setSecurityContextClassName( implClassName );

        boolean implCached = getBooleanProperty(props, SECURITY_CONTEXT_CACHED_PROP, true);
        setSecurityContextCached( implCached );

        String cacheProviderClassName = DEFAULT_CACHE_PROVIDER_CLASS_NAME;
        setCacheProviderClassName( cacheProviderClassName );

        boolean cacheAuthorizationInfo = getBooleanProperty( props, CACHE_AUTHORIZATION_INFO_PROP, true );
        setCacheAuthorizationInfo( cacheAuthorizationInfo );
    }


    /**
     * Helper method for getting a string property.  If a system property is specified it takes precidence,
     * otherwise it is retrieved from the properties collection.  If the property is still not found, the
     * specified default value is returned.
     */
    protected String getStringProperty(Properties props, String propName, String defaultValue) {
        String strValue = System.getProperty( propName );
        if( strValue == null ) {
            strValue = props.getProperty( propName, defaultValue );
        }
        return strValue;
    }

    /**
     * Helper method for getting a boolean property.  If a system property is specified it takes precidence,
     * otherwise it is retrieved from the properties collection.  If the property is still not found, the
     * specified default value is returned.
     */
    protected boolean getBooleanProperty(Properties props, String propName, boolean defaultValue) {
        String strValue = System.getProperty( propName );

        if( strValue == null ) {
            strValue = props.getProperty( propName );
        }

        if( strValue == null ) {
            return defaultValue;
        } else {
            return Boolean.parseBoolean( strValue );
        }
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/


    public String getSecurityContextClassName() {
        return securityContextClassName;
    }


    public void setSecurityContextClassName(String securityContextClassName ) {
        this.securityContextClassName = securityContextClassName;
    }


    public String getCacheProviderClassName() {
        return cacheProviderClassName;
    }


    public void setCacheProviderClassName(String cacheProviderClassName) {
        this.cacheProviderClassName = cacheProviderClassName;
    }


    /**
     * Returns whether or not the same <tt>SecurityContext</tt> implementation will be used each
     * time {@link SecurityContext#current()} is called.
     * <p/>
     * <p>The system default is <tt>true</tt>.
     * <p/>
     *
     * @return whether or not the same <tt>SecurityContext</tt> will be used each time
     * {@link SecurityContext#current()} is called.
     */
    public boolean isSecurityContextCached() {
        return securityContextCached;
    }


    /**
     * Sets whether or not the same <tt>SecurityContext</tt> implementation will be used each
     * time {@link SecurityContext#current()} is called.
     * <p/>
     * <p>The system default is <tt>true</tt>.
     * <p/>
     *
     * @param cached whether or not to cache the implementation instance.
     */
    public void setSecurityContextCached(boolean cached) {
        this.securityContextCached = cached;
    }


    public boolean isCacheAuthorizationInfo() {
        return cacheAuthorizationInfo;
    }


    public void setCacheAuthorizationInfo(boolean cacheAuthorizationInfo) {
        this.cacheAuthorizationInfo = cacheAuthorizationInfo;
    }

    public Properties getProperties() {
        return properties;
    }


    public void setProperties(Properties properties) {
        this.properties = properties;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Gets the default cache provider, instantiating one if necessary.  This call is synchronized
     * to ensure only one cache provider is created, so call this method as rarely as possible.
     * @return the default cache provider configured for this JSecurity configuration.
     */
     public CacheProvider getDefaultCacheProvider() {
         synchronized( this ) {
             if( defaultCacheProvider == null ) {
                 defaultCacheProvider = instantiateDefaultCacheProvider();
             }
         }
         return defaultCacheProvider;
     }


    /**
     * Instantiates the default cache provider as specified in the JSecurity configuration.
     * @return the default cache provider.
     */
     private CacheProvider instantiateDefaultCacheProvider() {

        String cacheProviderClassName = getCacheProviderClassName();

         if (logger.isDebugEnabled()) {
             logger.debug("Instantiating default cache provider of type [" + cacheProviderClassName + "]");
         }

        if( cacheProviderClassName == null ) {
            throw new IllegalStateException(
                "Default cache provider requested, but no cache provider class name specified in the configuration. " +
                "Please configure a cache provider.  See Configuration." );
        }

        try {
            Class clazz = Class.forName( cacheProviderClassName );
            Constructor constructor = clazz.getConstructor();

            CacheProvider cacheProvider = (CacheProvider) constructor.newInstance();
            cacheProvider.init( this );
            return cacheProvider;

        } catch (Exception e) {
            throw new CacheException("Error instantiating cache provider of type [" + cacheProviderClassName + "]", e);
        }

    }
}