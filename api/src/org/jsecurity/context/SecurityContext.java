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

import org.jsecurity.Configuration;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.DefaultConfiguration;
import org.jsecurity.session.Session;

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
     *  Will always be <tt>null</tt> if caching is turned off.
     */
    private static SecurityContext cachedImpl = null;


    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Security context settings used by this security context.
     * todo Can we remove this from being a static dependency without making the SecurityContext more difficult to use? -JCH 5/28/2006 
     */
    private static Configuration configuration;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public SecurityContext(){}

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public static Configuration getConfiguration() {
        if( configuration != null ) {
            return configuration;
        } else {
            configuration = new DefaultConfiguration();
        }
        return configuration;
    }


    public static void setConfiguration(Configuration configuration) {
        SecurityContext.configuration = configuration;
    }


    /*--------------------------------------------
    |        S T A T I C   M E T H O D S        |
    ============================================*/

    /**
     * Retrieves a SecurityContext instance based on a JSecurity implementation's configuration.
     *
     * @return the SecurityContext implementation.
     */
    private static SecurityContext getImpl() {

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if ( cl == null ) {
            cl = SecurityContext.class.getClassLoader();
        }

        SecurityContext impl;

        Configuration configuration = getConfiguration();

        if ( configuration.isSecurityContextCached() ) {
            synchronized (SecurityContext.class ) {
                if ( cachedImpl == null ) {
                    String implClassName = configuration.getSecurityContextClassName();
                    cachedImpl = instantiate( implClassName, cl );
                }
            }

            impl = cachedImpl;

        } else {
            String implClassName = configuration.getSecurityContextClassName();
            impl = instantiate( implClassName, cl );
        }

        return impl;
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