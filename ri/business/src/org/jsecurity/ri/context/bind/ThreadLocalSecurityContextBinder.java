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
package org.jsecurity.ri.context.bind;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.ri.util.ThreadContext;
import org.jsecurity.ri.context.bind.SecurityContextBinder;

/**
 * {@link org.jsecurity.ri.context.bind.SecurityContextBinder} implementation that binds
 * an authorization context to the calling thread using {@link org.jsecurity.ri.util.ThreadContext}
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
     * Binds the given context to a thread local.
     * @param context the context to be bound.
     */
    public void bindSecurityContext(SecurityContext context) {

        if (logger.isDebugEnabled()) {
            logger.debug("Binding authorization context [" + context + "] to the thread local context...");
        }

        ThreadContext.put( ThreadContext.SECURITY_CONTEXT_KEY, context );
    }
}