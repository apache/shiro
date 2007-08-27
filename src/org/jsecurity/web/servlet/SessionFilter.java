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
package org.jsecurity.web.servlet;

import org.jsecurity.session.SessionFactory;
import org.jsecurity.web.WebInterceptor;
import org.jsecurity.web.support.SessionWebInterceptor;

/**
 * Filter that is used to ensure a {@link org.jsecurity.session.Session} for the current user exists
 * on every request.  It should only be used if you always want a session to exist for the urls this Filter
 * intercepts.
 *
 * <p>It must be subclassed to retrieve a {@link SessionFactory} instance in an
 * application-dependent manner (e.g. from Spring, from the subclass directly, etc).
 *
 * <p>Must be configured <em>before</em> a {@link SecurityContextFilter} in the filter chain.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class SessionFilter extends WebInterceptorFilter {

    protected WebInterceptor createWebInterceptor() throws Exception {
        SessionWebInterceptor interceptor = new SessionWebInterceptor();
        interceptor.setSessionFactory( getSessionFactory() );
        interceptor.init();
        return interceptor;
    }

    protected abstract SessionFactory getSessionFactory();
}
