/*
 * Copyright (C) 2005 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.context;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.util.Properties;

/**
 * <p>The <code>SecurityContext</code> is the programmatic entry point into the JSecurity API. This
 * class provides access to the core services of JSecurity, such as the {@link
 * org.jsecurity.session.SessionFactory}, {@link org.jsecurity.authc.Authenticator}, {@link
 * org.jsecurity.authz.Authorizer}, etc. as well as current context of the calling code, such as its
 * {@link org.jsecurity.session.Session} and {@link org.jsecurity.authz.AuthorizationContext}</p>
 * <p/>
 * <p>To gain access to a <code>SecurityContext</code> instance, the following code should be
 * executed:
 * <p/>
 * <blockquote><pre>SecurityContext context = SecurityContext.getInstance();</pre></blockquote>
 * The returned <code>SecurityContext</code> instance will be an implementation from the JSecurity
 * implementation.  The <code>SecurityContext</code> is obtained using a {@link
 * SecurityContextFactory} that is implemented by the JSecurity implementation provider.</p>
 * <p/>
 * <p>The algorithm used in retrieving a <code>SecurityContext</code> using a {@link
 * SecurityContextFactory} is described in detail in the {@link #getContext(ClassLoader)}
 * JavaDoc.</p>
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @see SecurityContextFactory
 * @since 0.1
 */
public abstract class SecurityContext {

    /*--------------------------------------------
     |             C O N S T A N T S             |
     ============================================*/
    /**
     * Name of the system property or file property that determines the class name of the {@link
     * SecurityContextFactory} implementation class to use.
     */
    private static final String SECURITY_CONTEXT_FACTORY_PROP = "security.context.factory.class";

    /**
     * Name of the JSecurity properties file to be loaded.  This file should contain properties
     * telling JSecurity how to create a security context.
     */
    private static final String JSECURITY_PROPS_FILE = "jsecurity.properties";

    private static boolean factoryCached = true;

    /** Will always be <tt>null</tt> if caching is turned off (i.e. factoryCached == false); */
    private static SecurityContextFactory factory = null;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
     |        S T A T I C   M E T H O D S        |
     ============================================*/

    /**
     * Returns whether or not the same <tt>SecurityContextFactory</tt> will be used each time {@link
     * #getContext()} is called.
     * <p/>
     * <p>The system default is <tt>true</tt>.
     * <p/>
     * <p>Note: this does <em>not</em> determine whether or not each call to {@link #getContext()}
     * returns a cached <tt>SecurityContext</tt> each time.  That is determined by the Factory
     * implementation.
     *
     * @return whether or not the same <tt>SecurityContextFactory</tt> will be used each time {@link
     *         #getContext()} is called.
     */
    public static boolean isFactoryCached() {
        return factoryCached;
    }

    /**
     * Sets whether or not the same <tt>SecurityContextFactory</tt> will be used each time {@link
     * #getContext()} is called. <p>The system default is <tt>true</tt>.
     * <p/>
     * <p>Note: this does <em>not</em> determine whether or not each call to {@link #getContext()}
     * returns a cached <tt>SecurityContext</tt> each time.  That is determined by the Factory
     * implementation.
     *
     * @param cached whether or not to cache the factory instance.
     */
    public static void setFactoryCached( boolean cached ) {
        factoryCached = cached;
    }


    /**
     * Retrieves a {@link SecurityContext} instance based on a JSecurity implementation's
     * <tt>SecurityContextFactory</tt>.
     *
     * @return the current SecurityContext.
     */
    public static SecurityContext getContext() {

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if ( cl == null ) {
            cl = SecurityContext.class.getClassLoader();
        }
        return getContext( cl );
    }

    private static SecurityContext getContext( ClassLoader cl ) {

        SecurityContext context = null;

        if ( isFactoryCached() ) {
            if ( factory != null ) {
                context = factory.getContext( cl );
            }
        } else {
            String factoryClassName = getFactoryClassName( cl );
            SecurityContextFactory factory = getFactory( factoryClassName, cl );
            context = factory.getContext( cl );
        }

        if ( context == null ) {
            throw new SecurityContextException( "SecurityContext returned by factory was null." );
        }

        return context;
    }

    private static String getFactoryClassName( ClassLoader cl ) {
        String factoryClassName = System.getProperty( SECURITY_CONTEXT_FACTORY_PROP );

        if ( factoryClassName == null ) {

            InputStream propsFileIs = cl.getResourceAsStream( JSECURITY_PROPS_FILE );
            Properties props = new Properties();
            try {
                props.load( propsFileIs );
            } catch ( IOException e ) {
                String msg = "No [" + SECURITY_CONTEXT_FACTORY_PROP + "] system property " +
                             "is defined and [" + JSECURITY_PROPS_FILE + "] cannot be " +
                             "loaded from the classloader.  A SecurityContextFactory cannot " +
                             "be created.";
                throw new SecurityContextException( msg );
            }

            factoryClassName = props.getProperty( SECURITY_CONTEXT_FACTORY_PROP );

        }

        if ( factoryClassName == null || factoryClassName.length() == 0 ) {
            String msg = "No [" + SecurityContextFactory.class.getName() + "] implementation " +
                         "class was found configured in the system.  The factory " +
                         "implementation should normally be specified by including the " +
                         "JSecurity implementation JAR in the classpath.  The factory can " +
                         "also be specified by setting the [" + SECURITY_CONTEXT_FACTORY_PROP +
                         "] system property or manually including a jsecurity.properties file " +
                         "at the root of the classpath.";
            throw new SecurityContextException( msg );
        }

        return factoryClassName;

    }


    /**
     * Obtains a {@link SecurityContextFactory} instance of the specified factory class name,
     * loading any necessary classes using the given class loader.
     *
     * @param factoryClassName the class name of the factory implementation that should be
     *                         obtained.
     * @param cl               the class loader to use if any classes must be loaded.
     *
     * @return a {@link SecurityContextFactory} implementation of the specified type.
     */
    private static SecurityContextFactory getFactory( String factoryClassName, ClassLoader cl ) {
        if ( isFactoryCached() ) {
            if ( factory == null ) {
                factory = instantiateFactory( factoryClassName, cl );
            }
            return factory;
        } else {
            return instantiateFactory( factoryClassName, cl );
        }
    }

    private static SecurityContextFactory instantiateFactory( String factoryClassName,
                                                              ClassLoader cl ) {
        SecurityContextFactory factory;
        try {

            Class factoryClass = cl.loadClass( factoryClassName );
            factory = (SecurityContextFactory)factoryClass.newInstance();

        } catch ( ClassNotFoundException e ) {
            String msg = "Factory class [" + factoryClassName + "] could not be found.  No " +
                         "SecurityContext can be loaded.";
            throw new SecurityContextException( msg, e );
        } catch ( IllegalAccessException e ) {
            String msg = "Factory class [" + factoryClassName + "] constructor could not be " +
                         "accessed.  SecurityContext cannot be loaded.";
            throw new SecurityContextException( msg, e );
        } catch ( InstantiationException e ) {
            String msg = "Factory class [" + factoryClassName + "] could not be instantiated.  " +
                         "SecurityContext cannot be loaded.";
            throw new SecurityContextException( msg, e );
        }

        return factory;
    }

    /*--------------------------------------------
    |     A B S T R A C T   M E T H O D S       |
    ============================================*/
    public abstract SessionFactory getSessionFactory();

    public abstract Authenticator getAuthenticator();

    public abstract Authorizer getAuthorizer();

    public abstract Session getCurrentSession();

    public abstract AuthorizationContext getCurrentAuthContext();
}