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
package org.jsecurity.session.event;

/**
 * Listener interface to be implemented by objects to be notified of
 * events related to session events.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface SessionEventListener {

    /**
     * Notification callback that a {@link org.jsecurity.session.Session Session} has started.
     * @param event the event associated with the <tt>Session</tt> being started.
     */
    void sessionStarted( SessionEvent event );

    /**
     * Notification callback that a {@link org.jsecurity.session.Session Session} has been
     * invalidated (stopped).  A <tt>Session</tt> may be invalidated for a number of reasons,
     * including user log-outs or explicitly invalidation.
     *
     * @param event the event generated when a <tt>Session</tt> has been invalidated (stopped).
     *
     * @see org.jsecurity.session.Session#stop() Session.stop()
     */
    void sessionStopped( SessionEvent event );

    /**
     * Notification callback that a {@link org.jsecurity.session.Session Session} has expired.
     * @param event the event generated when a <tt>Session</tt> expires.
     */
    void sessionExpired( SessionEvent event );

}
