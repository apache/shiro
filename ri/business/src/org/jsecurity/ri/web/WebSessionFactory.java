/*
 * Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.ri.web;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A <tt>WebSessionFactory</tt> can init or acquire
 * {@link org.jsecurity.session.Session session}s in the Web tier of an application via
 * {@link javax.servlet.http.HttpServletRequest HttpServletRequest}s.
 *
 * <p>Most implementations of this interface will act as a wrapper, delegating
 * session creation and acquisition duties to an underlying JSecurity
 * {@link org.jsecurity.session.SessionFactory SessionFactory}, obtaining any information required
 * to do so from the <tt>HttpServletRequest</tt>.   This allows a unified
 * Session management layer in the business tier (where we think it belongs) accessible by
 * any client technology, not just web-based ones.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface WebSessionFactory {

    /**
     * Creates a <tt>Session</tt> based on a HTTP request.
     *
     * <p>Implementations of this interface might acquire the IP address associated with
     * the HTTP Request and simply delegate to
     * {@link org.jsecurity.session.SessionFactory#start(java.net.InetAddress)
     * SessionFactory.init(java.net.InetAddress)} (although this is not a strict
     * requirement - the session may be created in any number of ways).
     * @param request the current request being processed.
     * @param response the current response being generated.
     * @return a new <tt>Session</tt> based on the specified <tt>request</tt>
     */
    Session start( HttpServletRequest request, HttpServletResponse response );

    /**
     * Returns the <tt>Session</tt> associated with the given <tt>HttpServletRequest</tt>, or
     * <tt>null</tt> if no <tt>Session</tt> could be associated with the request.
     *
     * <p>Because HTTP is a stateless protocol, this method must rely on web-based means of
     * maintaining state to acquire a handle to a Session.  This most likely means acquiring the
     * JSecurity {@link org.jsecurity.session.Session#getSessionId() session id} from the
     * request itself (e.g. as a request parameter), from a {@link javax.servlet.http.Cookie
     * Cookie} or from the {@link javax.servlet.http.HttpSession HttpSession} itself.  Once an
     * id is obtained, the <tt>Session</tt> can be acquired by delegating the call to an underlying
     * {@link org.jsecurity.session.SessionFactory#getSession(java.io.Serializable)
     * SessionFactory.getSession(Serializable sessionId)} method call.  (This is not a strict
     * requirement, but merely suggests how it might commonly be done).
     *
     * <p>It is important to note that the <tt>HttpSession</tt> should only ever be
     * used to store a handle to the JSecurity <tt>Session</tt> to eliminate dependencies on
     * the web tier.  A JSecurity Session should be viewed as a client-agnostic replacement
     * for the <tt>HttpSession</tt>.
     *
     * @param request the current request being processed
     * @param response the current response being generated.
     * @return the <tt>Session</tt> associated with the request, or <tt>null</tt> if no
     * <tt>Session</tt> can be acquired.
     */
    Session getSession( HttpServletRequest request, HttpServletResponse response )
        throws InvalidSessionException, AuthorizationException;
}
