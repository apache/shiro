/*
 * Copyright (C) 2005 Les A. Hazlewood
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
package org.jsecurity.authc;

import java.io.Serializable;

/**
 * An authentication token is any representation of a user's principals and their supporting
 * credentials that an {@link Authenticator} would need to perform an authentication.  It is
 * a consolidation of the user principals and credentials submitted to the system by the user.
 *
 * <p>Common implementations of this class would have username/password combinations,
 * userid/public key combinations, or anything else you can think of.  The token can be anything
 * needed by an {@link Authenticator} to authenticate properly.
 *
 * <p>If you are familiar with JAAS, this class behaves in the same way as a
 * {@link javax.security.auth.callback.Callback} does, but without the imposition of JAAS login
 * symantics (such as requiring you to implement a
 * {@link javax.security.auth.callback.CallbackHandler CallbackHandler} and all the framework that
 * implies).
 *
 * <p>You are free to acquire a user's principals and credentials however you wish and
 * then submit them to the JSecurity framework in the form of an implementation of this class.  We
 * also think this class's name more accurately reflects its true purpose in a login framework, 
 * whereas <em>Callback</em> is less obvious.
 *
 * <p>Lastly, this interface extends <tt>Serializable</tt>, as it is quite often the case that
 * authentication submissions are done in client-server systems, where the token would be
 * created on the client tier and sent over the wire to a remote server where the actual
 * authentication process occurs.
 *
 * @author Les Hazlewood
 */
public interface AuthenticationToken extends Serializable {
}
