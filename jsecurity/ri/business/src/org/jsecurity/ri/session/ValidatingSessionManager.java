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
package org.jsecurity.ri.session;

import org.jsecurity.session.InvalidSessionException;

import java.io.Serializable;

/**
 * A ValidatingSessionManager is a SessionManager that can proactively validate any or all sessions
 * that may be expired.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface ValidatingSessionManager extends SessionManager {

    /**
     * Performs session validation for all open/active sessions in the system (those that
     * have not been stopped or expired), and validates each one.  If a session is
     * found to be invalid (e.g. it has expired), it is updated and saved to the EIS.
     *
     * <p>This method is necessary in order to handle orphaned sessions and is expected to be run at
     * a regular interval, such as once an hour, once a day or once a week, etc.
     * The &quot;best&quot; frequency to run this method is entirely dependent upon the application
     * and would be based on factors such as performance, average number of active users, hours of
     * least activity, and other things.
     *
     * <p>Most enterprise applications use a request/response programming model.
     * This is obvious in the case of web applications due to the HTTP protocol, but it is
     * equally true of remote client applications making remote method invocations.  The server
     * essentially sits idle and only &quot;works&quot; when responding to client requests and/or
     * method invocations.  This type of model is particularly efficent since it means the
     * security system only has to validate a session during those cases.  Such
     * &quot;lazy&quot; behavior enables the system to lie stateless and/or idle and only incur
     * overhead for session validation when necessary.
     *
     * <p>However, if a client forgets to log-out, or in the event of a server failure, it is
     * possible for sessions to be orphaned since no further requests would utilize that session.
     * Because of these lower-probability cases, it is required to regularly clean-up the sessions
     * maintained by the system.
     *
     * <p>Even in applications that aren't primarily based on a request/response model,
     * such as those that use enterprise asynchronous messaging (where data is pushed to
     * a client without first receiving a client request), it is almost always acceptable to
     * utilize this lazy approach and run this method at defined interval.
     *
     * <p>Systems that want to proactively validate individual sessions <em>without</em>
     * updating a session's {@link org.jsecurity.session.Session#getLastAccessTime() last access time} may call the
     * {@link #validateSession(Serializable) validateSession} method.  Note that even these
     * proactive systems, this {@link #validateSessions()} method should be invoked regularaly
     * anyway to <em>guarantee</em> no orphans exist.
     *
     * <p><b>Note:</b> It is <em>highly</em> recommended that this method be called by a
     * sophisticated scheduling mechanism such as {@link java.util.Timer} (not recommended
     * in managed J2EE environments) or via 3rd-party
     * scheduling tools such as the
     * <a href="http://www.opensymphony.com/quartz/">Quartz Enterprise Job Scheduler</a>
     * (highly recommended in all environments).
     */
    void validateSessions();

    /**
     * Proactively validates a single session.
     *
     * @param sessionId the id of the session to validate
     * @throws org.jsecurity.session.InvalidSessionException if, upon validation, the session was stopped or expired.
     */
    void validateSession( Serializable sessionId ) throws InvalidSessionException;


}
