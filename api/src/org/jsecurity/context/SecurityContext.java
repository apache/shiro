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
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.Session;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * <p>The <code>SecurityContext</code> is the programmatic entry point into the JSecurity API. This
 * class provides access to the current context of the calling code, such as its
 * {@link org.jsecurity.session.Session} and {@link org.jsecurity.authz.AuthorizationContext}</p>
 *
 * @since 0.1

 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class SecurityContext {

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
     *  Concrete implementation instance
     */
    private static SecurityContext impl = null;


    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public SecurityContext(){}

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |        S T A T I C   M E T H O D S        |
    ============================================*/

    /**
     * Retrieves a SecurityContext instance based on a JSecurity implementation's configuration.
     *
     * @return the SecurityContext implementation.
     */
    private static SecurityContext getImpl() {
        if ( SecurityContext.impl != null ) {
            return SecurityContext.impl;
        }

        //not explicitly set - attempt to construct an instance from a properties file
        //on the classpath.  If users of JSecurity don't like this approach, they need to
        //explicitly set the SecurityContext via the static setSecurityContext(...) method.

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if ( cl == null ) {
            cl = SecurityContext.class.getClassLoader();
        }

        String implClassName = getImplClassName( cl );
        SecurityContext impl = instantiate( implClassName, cl );

        setSecurityContext( impl );

        return impl;
    }

    private static String getImplClassName( ClassLoader cl ) {
        boolean sysProp = true;
        String implClassName = System.getProperty( SECURITY_CONTEXT_CLASS_NAME_PROP );

        if ( implClassName == null ) {
            InputStream propsFileIs = cl.getResourceAsStream( JSECURITY_PROPS_FILE );
            Properties props = new Properties();
            try {
                props.load( propsFileIs );
            } catch ( IOException e ) {
                String msg = "No '" + SECURITY_CONTEXT_CLASS_NAME_PROP + "' system property " +
                             "is defined and " + JSECURITY_PROPS_FILE + " cannot be " +
                             "loaded from the classloader.  A " + SecurityContext.class.getName() +
                             "instance cannot be implicitly created.  To avoid this exception, you " +
                             "may do one of three things:\n" +
                             "\t 1. Explicitly set a SecurityContext implementation via the " +
                             "static SecurityContext.setSecurityContext method\n" +
                             "\t 2. Set the '" + SECURITY_CONTEXT_CLASS_NAME_PROP + "' " +
                             "system property with the value of the implementation to instantiate " +
                             "(must have a default no-arg constructor)\n" +
                             "\t 3. Make a '" + JSECURITY_PROPS_FILE + "' file available at the " +
                             "root of the classpath.  This file must have a property named '" +
                             SECURITY_CONTEXT_CLASS_NAME_PROP + "' with a value of the " +
                             "implementation class to instantiate (must have a default " +
                             "no-arg constructor)";
                throw new SecurityContextException( msg );
            }

            implClassName = props.getProperty( SECURITY_CONTEXT_CLASS_NAME_PROP );
            sysProp = false;
        }

        if ( implClassName == null || implClassName.length() == 0 ) {
            String msg = "No [" + SecurityContext.class.getName() + "] implementation " +
                         "class value was specified for the '" +
                         SECURITY_CONTEXT_CLASS_NAME_PROP + "' " +
                         (sysProp ? "system property." :
                                    "property in " + JSECURITY_PROPS_FILE + "." ) +
                         "  SecurityContext cannot be created.";
            throw new SecurityContextException( msg );
        }

        return implClassName;

    }

    private static SecurityContext instantiate( String implClassName, ClassLoader cl ) {
        SecurityContext impl;
        try {

            Class implClass = cl.loadClass( implClassName );
            impl = (SecurityContext)implClass.newInstance();

        } catch ( ClassNotFoundException e ) {
            String msg = "SecurityContext implementation class [" + implClassName + "] could not " +
                         "be found.  SecurityContext cannot be created.";
            throw new SecurityContextException( msg, e );
        } catch ( IllegalAccessException e ) {
            String msg = "SecurityContext implementation class [" + implClassName + "] constructor " +
                "could not be accessed.  SecurityContext cannot be created.";
            throw new SecurityContextException( msg, e );
        } catch ( InstantiationException e ) {
            String msg = "SecurityContext implementation class [" + implClassName + "] could not be " +
                "instantiated.";
            throw new SecurityContextException( msg, e );
        }

        return impl;
    }

    public static SecurityContext current() {
        return getImpl();
    }

    public static synchronized void setSecurityContext( SecurityContext impl )
        throws AuthorizationException {
        if ( SecurityContext.impl == null ) {
            SecurityContext.impl = impl;
        } else {
            AuthorizationContext authzCtx = SecurityContext.impl.getAuthorizationContext();
            if ( authzCtx != null ) {
                RuntimePermission setSecCtx = new RuntimePermission( "setSecurityContext" );
                authzCtx.checkPermission( setSecCtx );
            }
            //if we're at this point in the code, there was no exception (i.e. the current user
            //is allowed to override the current SecurityContext), so set it:
            SecurityContext.impl = impl;
        }
    }

    /*--------------------------------------------
    |     A B S T R A C T   M E T H O D S       |
    ============================================*/

    /**
     * Returns the <tt>Session</tt> currently accessible by the application, or <tt>null</tt>
     * if there is no session associated with the current execution.
     *
     * <p>The &quot;currently accessible&quot; Session is retrieved in an
     * implementation-specific manner.
     *
     * <p>For example, in a multithreaded server application, such as in a J2EE application
     * server or Servlet container, a <tt>Session</tt> might be bound to the currently-executing
     * server thread via a {@link ThreadLocal ThreadLocal}.  A web application may access the
     * JSecurity Session via a handle stored in a {@link javax.servlet.http.Cookie Cookie}.  A
     * standalone Swing application may access the <tt>Session</tt> via static memory.
     *
     * <p>These scenarios are just examples based on how a JSecurity implementation might accomplish
     * these things depending on an application's deployment environment.
     *
     * @return the <tt>Session</tt> currently accessible by the application, or <tt>null</tt>
     * if there is no session associated with the current execution.
     */
    public abstract Session getSession();

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
     */
    public abstract AuthorizationContext getAuthorizationContext();

    /**
     * Invalidates any JSecurity entities (such as a {@link Session Session} and a
     * {@link AuthorizationContext AuthorizationContext}) associated with the current execution.
     *
     * The entities for &quot;current execution&quot; are obtained in an implementation-specific
     * manner.  Please see the {@link #getSession() getSession() JavaDoc} for an explanation of
     * how this information is obtained.
     *
     * @see #getSession
     */
    public abstract void invalidate();
}