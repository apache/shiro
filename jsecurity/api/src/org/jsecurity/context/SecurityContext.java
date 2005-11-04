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
import org.jsecurity.session.SecureSession;
import org.jsecurity.session.Session;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * <p>The <code>SecurityContext</code> is the programmatic entry point into the JSecurity API. This
 * class provides access to the current context of the calling code, such as its
 * {@link org.jsecurity.session.Session} and {@link org.jsecurity.authz.AuthorizationContext}</p>
 * <p/>
 * <p>The algorithm used in retrieving a <code>SecurityContext</code> using a
 * {@link SecurityContextAccessor} is described in detail in the {@link #getAccessor()}
 * JavaDoc.</p>
 *
 * @since 0.1
 * @see SecurityContextAccessor

 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class SecurityContext {

    /*--------------------------------------------
     |             C O N S T A N T S             |
     ============================================*/
    /**
     * Name of the system property or file property that determines the class name of the {@link
     * SecurityContextAccessor} implementation class to use.
     */
    private static final String SECURITY_CONTEXT_ACCESSOR_PROP = "security.context.accessor.class";

    /**
     * <p>This property determines whether or not the security context accessor should be cached.
     * The JSecurity implementation is responsible for configuring whether or not caching of
     * the accessor is allowed.  The default value of this property is true for performance
     * reasons, although implementations are allowed to override the value either through
     * the properties file or a system property.</p>
     * <p>This property should be set to "false" to disable caching of the accessor.  Any other value
     * will leave caching enabled.</p>
     */
    private static final String SECURITY_CONTEXT_ACCESSOR_CACHED_PROP = "security.context.accessor.cached";

    /**
     * Name of the JSecurity properties file to be loaded.  This file should contain properties
     * telling JSecurity how to create a security context.
     */
    private static final String JSECURITY_PROPS_FILE = "jsecurity.properties";

    private static boolean accessorCached = true;

    /** Will always be <tt>null</tt> if caching is turned off (i.e. accessorCached == false); */
    private static SecurityContextAccessor cachedAccessor = null;


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
     * Returns whether or not the same <tt>SecurityContextAccessor</tt> will be used each time {@link
     * #getAccessor()} is called.
     * <p/>
     * <p>The system default is <tt>true</tt>.
     * <p/>
     * <p>Note: this does <em>not</em> determine whether or not each call to {@link #getAccessor()}
     * returns a cached <tt>SecurityContext</tt> each time.  That is determined by the accessor
     * implementation.
     *
     * @return whether or not the same <tt>SecurityContextAccessor</tt> will be used each time {@link
     *         #getAccessor()} is called.
     */
    protected static boolean isAccessorCached() {
        return accessorCached;
    }

    /**
     * Sets whether or not the same <tt>SecurityContextAccessor</tt> will be used each time {@link
     * #getAccessor()} is called. <p>The system default is <tt>true</tt>.
     * <p/>
     * <p>Note: this does <em>not</em> determine whether or not each call to {@link #getAccessor()}
     * returns a cached <tt>SecurityContext</tt> each time.  That is determined by the accessor
     * implementation.
     *
     * @param cached whether or not to cache the accessor instance.
     */
    protected static void setAccessorCached( boolean cached ) {
        accessorCached = cached;
    }


    /**
     * Retrieves a {@link SecurityContextAccessor} instance based on a JSecurity implementation's
     * <tt>SecurityContextAccessor</tt>.
     *
     * @return the current SecurityContextAccessor
     */
    private static SecurityContextAccessor getAccessor() {

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if ( cl == null ) {
            cl = SecurityContext.class.getClassLoader();
        }

        SecurityContextAccessor accessor;

        if ( isAccessorCached() ) {
            synchronized (SecurityContext.class ) {
                if ( cachedAccessor == null ) {
                    String accessorClassName = getAccessorClassName( cl );
                    cachedAccessor = instantiateAccessor( accessorClassName, cl );
                }
            }

            accessor = cachedAccessor;

        } else {
            String accessorClassName = getAccessorClassName( cl );
            accessor = instantiateAccessor( accessorClassName, cl );
        }

        return accessor;
    }

    private static String getAccessorClassName( ClassLoader cl ) {
        String accessorClassName = System.getProperty( SECURITY_CONTEXT_ACCESSOR_PROP );

        if ( accessorClassName == null ) {

            InputStream propsFileIs = cl.getResourceAsStream( JSECURITY_PROPS_FILE );
            Properties props = new Properties();
            try {
                props.load( propsFileIs );
            } catch ( IOException e ) {
                String msg = "No [" + SECURITY_CONTEXT_ACCESSOR_PROP + "] system property " +
                             "is defined and [" + JSECURITY_PROPS_FILE + "] cannot be " +
                             "loaded from the classloader.  A " + SecurityContextAccessor.class.getName() + " " +
                             "cannot be created.";
                throw new SecurityContextException( msg );
            }

            accessorClassName = props.getProperty( SECURITY_CONTEXT_ACCESSOR_PROP );

            String strAccessorCached = props.getProperty( SECURITY_CONTEXT_ACCESSOR_CACHED_PROP );
            if( "false".equals( strAccessorCached ) ) {
                setAccessorCached( false );
            }

        }

        if ( accessorClassName == null || accessorClassName.length() == 0 ) {
            String msg = "No [" + SecurityContextAccessor.class.getName() + "] implementation " +
                         "class was found configured in the system.  The accessor " +
                         "implementation should normally be specified by including the " +
                         "JSecurity implementation JAR in the classpath.  The accessor can " +
                         "also be specified by setting the [" + SECURITY_CONTEXT_ACCESSOR_PROP +
                         "] system property or manually including a jsecurity.properties file " +
                         "at the root of the classpath.";
            throw new SecurityContextException( msg );
        }

        return accessorClassName;

    }

    private static SecurityContextAccessor instantiateAccessor( String accessorClassName,
                                                                ClassLoader cl ) {
        SecurityContextAccessor accessor;
        try {

            Class accessorClass = cl.loadClass( accessorClassName );
            accessor = (SecurityContextAccessor)accessorClass.newInstance();

        } catch ( ClassNotFoundException e ) {
            String msg = "Accessor class [" + accessorClassName + "] could not be found.  " +
                         "SecurityContext cannot be loaded.";
            throw new SecurityContextException( msg, e );
        } catch ( IllegalAccessException e ) {
            String msg = "Accessor class [" + accessorClassName + "] constructor could not be " +
                         "accessed.  SecurityContext cannot be loaded.";
            throw new SecurityContextException( msg, e );
        } catch ( InstantiationException e ) {
            String msg = "Accessor class [" + accessorClassName + "] could not be instantiated.  " +
                         "SecurityContext cannot be loaded.";
            throw new SecurityContextException( msg, e );
        }

        return accessor;
    }

    /*--------------------------------------------
    |     A B S T R A C T   M E T H O D S       |
    ============================================*/

    /**
     * Returns the <tt>Session</tt> currently accessible by the application, or <tt>null</tt>
     * if there is no session associated with the current execution.
     *
     * <p>The term &quot;currently accessible&quot; means the Session returned by a
     * {@link SecurityContextAccessor SecurityContextAccessor} during runtime and is
     * implementation specific.
     *
     * <p>For example, in a multithreaded server application (such as in a J2EE application
     * server or Servlet container), a <tt>Session</tt> might be bound to the currently-executing
     * server thread via a {@link ThreadLocal ThreadLocal}.  A web application may access the
     * JSecurity Session via a handle in the {@link javax.servlet.http.HttpSession HttpSession}}.  A
     * standalone Swing application may access the <tt>Session</tt> via static memory.
     *
     * <p>These scenarios are just examples based on how a JSecurity implementation might accomplish
     * these things depending on an application's deployment environment.
     *
     * @return the <tt>Session</tt> currently accessible by the application, or <tt>null</tt>
     * if there is no session associated with the current execution.
     *
     * @see SecurityContextAccessor
     */
    public static SecureSession getSession() {
        return getAccessor().getSession();
    }

    /**
     * Returns the AuthorizationContext associated with the current authenticated user, or
     * <tt>null</tt> if the current user has not yet been authenticated (i.e. logged in).
     *
     * The &quot;current user&quot; is associated with this method call in an
     * implementation-specific manner.  Please see the {@link #getSession() getSession() JavaDoc}
     * for an explanation of how this information is obtained.
     *
     * @return the AuthorizationContext associated with the current authenticated user, or
     * <tt>null</tt> if the current user has not yet been authenticated (i.e. logged in).
     *
     * @see #getSession
     * @see SecurityContextAccessor
     */
    public static AuthorizationContext getAuthorizationContext() {
        return getAccessor().getAuthorizationContext();
    }

    /**
     * Invalidates any JSecurity entities (such as a {@link Session Session} and a
     * {@link AuthorizationContext AuthorizationContext}) associated with the current execution.
     *
     * The entities for &quot;current execution&quot; are obtained in an implementation-specific
     * manner.  Please see the {@link #getSession() getSession() JavaDoc} for an explanation of
     * how this information is obtained.
     *
     * @see #getSession
     * @see SecurityContextAccessor
     */
    public static void invalidate() {
        getAccessor().invalidate();
    }
}