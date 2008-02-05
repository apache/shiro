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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.SessionFactory;

/**
 * A <tt>SecurityManager</tt> is a convenience mechanism - it extends the {@link Authenticator},
 * {@link Authorizer}, and {@link SessionFactory} interfaces, thereby consolidating
 * these behaviors into a single interface.  This allows applications to interact with a single
 * <tt>SecurityManager</tt> component for all JSecurity operations.
 *
 * <p>In addition to the above the interfaces, two unique methods are provided by this interface,
 * {@link #login} and {@link #getSecurityContext}.  A SecurityContext is an encompassing component that utilizes
 * authentication, authorization, and session operations for a single Subject, and as such can only be managed by
 * <tt>A SecurityManager</tt> which is aware of all three operations (the 3 parent interfaces on the other hand
 * do not know of all operations to ensure a clean separation of concerns).
 *
 * @see DefaultSecurityManager
 *
 * @since 0.2
 * 
 * @author Les Hazlewood
 */
public interface SecurityManager extends Authenticator, Authorizer, SessionFactory {

    SecurityContext login( AuthenticationToken authenticationToken ) throws AuthenticationException;

    /**
     * Logs out the specified Subject/User from the system.
     *
     * @param subjectIdentifier the identifier of the subject/user to log out.
     */
    void logout( Object subjectIdentifier );

    /**
     * Returns the calling context's <tt>SecurityContext</tt>.
     * @return the calling context's <tt>SecurityContext</tt>.
     */
    SecurityContext getSecurityContext();
}