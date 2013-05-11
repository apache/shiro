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
package org.apache.shiro.mgt;

import org.apache.shiro.subject.Subject;

/**
 * Evaluates whether or not Shiro may use a {@code Subject}'s {@link org.apache.shiro.session.Session Session}
 * to persist that {@code Subject}'s internal state.
 * <p/>
 * It is a common Shiro implementation strategy to use a Subject's session to persist the Subject's identity and
 * authentication state (e.g. after login) so that information does not need to be passed around for any further
 * requests/invocations.  This effectively allows a session id to be used for any request or invocation as the only
 * 'pointer' that Shiro needs, and from that, Shiro can re-create the Subject instance based on the referenced Session.
 * <p/>
 * However, in purely stateless applications, such as some REST applications or those where every request is
 * authenticated, it is usually not needed or desirable to use Sessions to store this state (since it is in
 * fact re-created on every request).  In these applications, sessions would never be used.
 * <p/>
 * This interface allows implementations to determine exactly when a Session might be used or not to store
 * {@code Subject} state on a <em>per-Subject</em> basis.
 * <p/>
 * If you simply wish to enable or disable session usage at a global level for all {@code Subject}s, the
 * {@link DefaultSessionStorageEvaluator} should be sufficient.  Per-subject behavior should be performed in custom
 * implementations of this interface.
 *
 * @see Subject#getSession()
 * @see Subject#getSession(boolean)
 * @see DefaultSessionStorageEvaluator
 * @since 1.2
 */
public interface SessionStorageEvaluator {

    /**
     * Returns {@code true} if the specified {@code Subject}'s
     * {@link org.apache.shiro.subject.Subject#getSession() session} may be used to persist that Subject's
     * state, {@code false} otherwise.
     *
     * @param subject the {@code Subject} for which session state persistence may be enabled
     * @return {@code true} if the specified {@code Subject}'s
     *         {@link org.apache.shiro.subject.Subject#getSession() session} may be used to persist that Subject's
     *         state, {@code false} otherwise.
     * @see Subject#getSession()
     * @see Subject#getSession(boolean)
     */
    boolean isSessionStorageEnabled(Subject subject);

}
