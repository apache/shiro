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

/**
 * Accesses the currently accessible <tt>SecurityContext</tt> for the calling code.
 *
 * @deprecated call the {@link org.jsecurity.SecurityManager#getSecurityContext()} method instead.  This class will
 * be removed before JSecurity 1.0 final.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class SecurityUtils {

    private static SecurityManager securityManager = null; //expected to be set by framework code.

    public static void setSecurityManager( SecurityManager sm ) {
        securityManager = sm;
    }

    /**
     * Returns the currently accessible <tt>SecurityContext</tt> available to the calling code.
     *
     * <p>This method is provided as a way of obtaining a <tt>SecurityContext</tt> without having to resort to
     * implementation-specific methods.  It also allows the JSecurity team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     *
     * @deprecated call {@link org.jsecurity.SecurityManager#getSecurityContext()} instead.  This class will be
     * removed before 1.0 final.
     *
     * @return the currently accessible <tt>SecurityContext</tt> accessible to the calling code.
     */
    public static SecurityContext getSecurityContext() {
        return securityManager.getSecurityContext();
    }
}
