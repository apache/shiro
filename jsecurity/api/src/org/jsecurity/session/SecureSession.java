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
package org.jsecurity.session;

import org.jsecurity.authz.AuthorizationContext;

/**
 * Convenience interface that consolidates Session behavior and Authorization behavior for a
 * single component.
 *
 * <p>The benefit here is that if using JSecurity for integrated Session management and
 * Authentication/Authorization functionality, you only need to reference an implementation of this
 * common interface, instead of acquiring 2 objects to do perform session and authorization
 * behavior.
 *
 * <p><b>Usage Note:</b> Authorization behavior on implementations of this interface can only be
 * executed after a successful log-in since authorization must be associated with a known
 * account identity.  If attempting to call any {@link AuthorizationContext AuthorizationContext}
 * methods on an instance when <em>un</em>authenticated, an
 * {@link org.jsecurity.authz.UnauthenticatedException UnauthenticatedException} will be thrown.
 * If you want to ensure this won't happen, you can cast an instance of this interface to
 * a {@link Session Session} to enforce compile-time safety against calling those methods until
 * after you can guarantee a successful authentication.
 *
 * @since 1.0
 * @author Les Hazlewood
 */
public interface SecureSession extends Session, AuthorizationContext {
}
