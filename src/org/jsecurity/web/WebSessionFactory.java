/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.web;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.Session;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A <tt>WebSessionFactory</tt> can acquire application {@link org.jsecurity.session.Session session}s in the
 * Web tier via {@link javax.servlet.ServletRequest ServletRequest}s.
 *
 * <p>Most implementations of this interface will act as a wrapper, delegating
 * actual session acquisition duties to underlying
 * {@link org.jsecurity.session.SessionFactory SessionFactory} methods, but obtaining any information required
 * to do so from the <tt>ServletRequest</tt>.   This allows a unified
 * Session management layer in the business tier (where we think it belongs) accessible by
 * any client technology, not just web-based ones.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface WebSessionFactory {

    /**
     * Creates a {@link Session Session} based on a Servlet request.
     *
     * @param request the current request being processed.
     * @param response the current response being generated.
     * @return a new <tt>Session</tt> based on the specified <tt>request</tt>
     */
    Session start( ServletRequest request, ServletResponse response );

    /**
     * Returns the <tt>Session</tt> associated with the given <tt>ServletRequest</tt>, or
     * <tt>null</tt> if no <tt>Session</tt> was associated with the request.
     *
     * @param request the current request being processed
     * @param response the current response being generated.
     * @return the <tt>Session</tt> associated with the request, or <tt>null</tt> if no
     * <tt>Session</tt> can be acquired.
     * @throws AuthorizationException if the subject or machine associated with the current request is not authorized
     * to acquire the session associated with the request.
     */
    Session getSession( ServletRequest request, ServletResponse response ) throws AuthorizationException;
}
