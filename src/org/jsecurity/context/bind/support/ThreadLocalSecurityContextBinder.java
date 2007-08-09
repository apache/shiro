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
package org.jsecurity.context.bind.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.bind.SecurityContextBinder;
import org.jsecurity.util.ThreadContext;

/**
 * {@link org.jsecurity.context.bind.SecurityContextBinder} implementation that binds
 * a <tt>SecurityContext</tt> to the calling thread using a thread-local.  This implementation
 * should almost always be used in server-side multi-threaded environments such as web applications or enterprise
 * middleware.
 *
 * <p>Once the thread stack is finished executing (for example, at the end of a web
 * request), the application is responsible for ensuring the SecurityContext is available on subsequent requests.
 * Framework AOP
 * interceptors or Servlet Filters usually fulfill this role (e.g. by persistently storing the SecurityContext somewhere
 * for later access, or more commonly, reconstructing the SecurityContext on every request based on some critieria -
 * such as a user's id or sessionId - to maintain a stateless architecture).
 *
 * @see org.jsecurity.SecurityUtils
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class ThreadLocalSecurityContextBinder implements SecurityContextBinder {

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * Binds the given context to the calling thread via the {@link ThreadContext}.
     * @param context the context to be bound to the application for later access.
     */
    public void bindSecurityContext(SecurityContext context) {

        if (logger.isDebugEnabled()) {
            logger.debug("Binding SecurityContext [" + context + "] to the thread local context...");
        }

        ThreadContext.bind( context );
    }
}