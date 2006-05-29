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
package org.jsecurity.ri.authc.event;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.module.AuthenticationInfo;

/**
 * An AuthenticationEventFactory functions as its name implies - a Factory design pattern
 * implementation that generates AuthenticationEvents.  After created, these events can then be
 * sent to interested parties via an {@link AuthenticationEventSender}.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface AuthenticationEventFactory {

    /**
     * Creates an AuthenticationEvent after a failed authentication attempt.
     *
     * @param token - the authentication token submitted during the authentication attempt.
     * @param ex - the exception thrown during the attempt.
     * @return the AuthenticationEvent to send due to the failed attempt.
     */
    AuthenticationEvent createFailureEvent( AuthenticationToken token, AuthenticationException ex );

    /**
     * Creates an AuthenticationEvent after a successful authentication (log-in).
     * @param token the authentication token submitted during the authentication attempt.
     * @param info the authentication info created in response to the successful token submission.
     * @return the AuthenticationEvent to send due to the successful log-in attempt.
     */
    AuthenticationEvent createSuccessEvent( AuthenticationToken token, AuthenticationInfo info );

}
