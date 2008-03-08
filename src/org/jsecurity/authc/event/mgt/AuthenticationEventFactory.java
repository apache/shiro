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
package org.jsecurity.authc.event.mgt;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.event.AuthenticationEvent;

/**
 * An AuthenticationEventFactory functions as its name implies - a Factory design pattern
 * implementation that generates AuthenticationEvents.  After created, these events can then be
 * sent to interested {@link org.jsecurity.authc.event.AuthenticationEventListener}s.
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
     * @see org.jsecurity.authc.event.SuccessfulAuthenticationEvent
     */
    AuthenticationEvent createFailureEvent( AuthenticationToken token, AuthenticationException ex );

    /**
     * Creates an AuthenticationEvent after a successful authentication (log-in).
     * @param token the authentication token submitted during the authentication attempt.
     * @param account the account data retrieved in response to the successful token submission.
     * @return the AuthenticationEvent to send due to the successful log-in attempt.
     * @see org.jsecurity.authc.event.FailedAuthenticationEvent
     */
    AuthenticationEvent createSuccessEvent( AuthenticationToken token, Account account );

    /**
     * Creates an AuthenticationEvent in response to a Subject logging out.
     *
     * @param subjectPrincipal the application-specific Subject/account identifier.
     * @return an AuthenticationEvent to send due to the Subject logging out.
     * @see org.jsecurity.authc.event.LogoutEvent
     */
    AuthenticationEvent createLogoutEvent(Object subjectPrincipal);
}
