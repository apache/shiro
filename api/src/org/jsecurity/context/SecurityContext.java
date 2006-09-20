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

import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.session.Session;

/**
 * <p>The <code>SecurityContext</code> is an application programmer's entry point into the JSecurity API. This
 * interface provides access to the security context of the current Subject (a.k.a. 'user' or 'account'), providing
 * support for authentication, authorization (access control), and {@link org.jsecurity.session.Session session}
 * management.
 *
 * @since 0.1

 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface SecurityContext extends Authenticator, AuthorizationContext {

    public abstract boolean isAuthenticated();

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