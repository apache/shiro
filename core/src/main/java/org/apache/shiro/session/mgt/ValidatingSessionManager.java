/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.session.mgt;

/**
 * A ValidatingSessionManager is a SessionManager that can proactively validate any or all sessions
 * that may be expired.
 *
 * @since 0.1
 */
public interface ValidatingSessionManager extends SessionManager {

    /**
     * Performs session validation for all open/active sessions in the system (those that
     * have not been stopped or expired), and validates each one.  If a session is
     * found to be invalid (e.g. it has expired), it is updated and saved to the EIS.
     * <p/>
     * This method is necessary in order to handle orphaned sessions and is expected to be run at
     * a regular interval, such as once an hour, once a day or once a week, etc.
     * The &quot;best&quot; frequency to run this method is entirely dependent upon the application
     * and would be based on factors such as performance, average number of active users, hours of
     * least activity, and other things.
     * <p/>
     * Most enterprise applications use a request/response programming model.
     * This is obvious in the case of web applications due to the HTTP protocol, but it is
     * equally true of remote client applications making remote method invocations.  The server
     * essentially sits idle and only &quot;works&quot; when responding to client requests and/or
     * method invocations.  This type of model is particularly efficient since it means the
     * security system only has to validate a session during those cases.  Such
     * &quot;lazy&quot; behavior enables the system to lie stateless and/or idle and only incur
     * overhead for session validation when necessary.
     * <p/>
     * However, if a client forgets to log-out, or in the event of a server failure, it is
     * possible for sessions to be orphaned since no further requests would utilize that session.
     * Because of these lower-probability cases, it might be required to regularly clean-up the sessions
     * maintained by the system, especially if sessions are backed by a persistent data store.
     * <p/>
     * Even in applications that aren't primarily based on a request/response model,
     * such as those that use enterprise asynchronous messaging (where data is pushed to
     * a client without first receiving a client request), it is almost always acceptable to
     * utilize this lazy approach and run this method at defined interval.
     * <p/>
     * Systems that want to proactively validate individual sessions may simply call the
     * {@link #getSession(SessionKey) getSession(SessionKey)} method on any
     * {@code ValidatingSessionManager} instance as that method is expected to
     * validate the session before retrieving it.  Note that even with proactive calls to {@code getSession},
     * this {@code validateSessions()} method should be invoked regularly anyway to <em>guarantee</em> no
     * orphans exist.
     * <p/>
     * <b>Note:</b> Shiro supports automatic execution of this method at a regular interval
     * by using {@link SessionValidationScheduler}s.  The Shiro default SecurityManager implementations
     * needing session validation will create and use one by default if one is not provided by the
     * application configuration.
     */
    void validateSessions();
}
