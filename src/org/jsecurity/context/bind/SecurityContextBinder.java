/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.context.bind;

import org.jsecurity.context.SecurityContext;

/**
 * <p>A <tt>SecurityContextBinder</tt> is responsible for binding an
 * {@link org.jsecurity.context.SecurityContext} object after authentication takes place
 * to the application so that it can be retrieved for later access.  For example, the
 * binder could bind the context to a thread local, HTTP cookie, static variable, etc.</p>
 *
 * <p>Typically another framework class would access this stored context to make it available in an easy manner
 * for application components.
 *
 * @see org.jsecurity.context.bind.support.ThreadLocalSecurityContextBinder
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface SecurityContextBinder {

    /**
     * Binds the authorization context to the application so that it is accessible to future access.
     * @param context the authorization context to bind.
     */
    void bindSecurityContext( SecurityContext context );

}