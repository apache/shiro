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

package org.jsecurity.authc.event;


/**
 * Listener interface to be implemented by objects to be notified of
 * events related to account authentication.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface AuthenticationEventListener {

    /**
     * Notification callback that an account has authenticated successfully.
     * @param event the event associated with the successful authentication attempt.
     */
    void accountAuthenticated( AuthenticationEvent event );

    /**
     * Notification callback that an account has logged-out.
     * @param event the event associated with the log-out.
     */
    void accountLoggedOut( AuthenticationEvent event );

    /**
     * Notification callback that an account authentication attempt had failed.
     * @param event the event associated with the failed authentication attempt.
     */
    void authenticationFailed( AuthenticationEvent event );

    /**
     * Notification callback that an account has been locked from further authentication
     * attempts (usually due to
     * too many failed authentication attempts).
     * @param event the event generated due to an account being locked.
     */
    void accountLocked( AuthenticationEvent event );

    /**
     * Notification callback that an account has been unlocked and is available for future
     * authentication attempts (usually by an administrator or after a certain time has passed).
     * @param event the event generated due to an account being unlocked.
     */
    void accountUnlocked( AuthenticationEvent event );

}

