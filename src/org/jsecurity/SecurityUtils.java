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
package org.jsecurity;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.SecurityContextException;
import org.jsecurity.util.ThreadContext;

/**
 * Simple utility class to perform common JSecurity operations in an application.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class SecurityUtils {

    /**
     * Returns the currently accessible <tt>SecurityContext</tt> available to the calling code.
     *
     * <p>This method is provided as a way of obtaining a <tt>SecurityContext</tt> without having to resort to
     * implementation-specific methods.  It also allows the JSecurity team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     *
     * <p><b>PLEASE NOTE:</b> Currently, this method should only be called in web and server-side environments.  If
     * you're operating in a standalone application environment, you should instead create your own SecurityUtils
     * class that returns the <tt>SecurityContext</tt> in your environment-specific manner.
     *
     * @return the currently accessible <tt>SecurityContext</tt> accessible to the calling code.
     */
    public static SecurityContext getSecurityContext() {
        SecurityContext secCtx = ThreadContext.getSecurityContext();
        if( secCtx == null ) {
            throw new SecurityContextException( "No security context is bound to the current thread.  " +
                    "Make sure that a SecurityContextWebInterceptor or SecurityContextFilter is configured." );
        }
        return secCtx;
    }
}
