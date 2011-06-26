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
 * A {@code SessionStorageEvaluator} implementation that allows Subject session usage to be enabled or disabled at a
 * global level for all subjects.
 * <p/>
 * This implementation does not perform per-{@code Subject} behavior - it simply enables or disables session storage
 * for all {@code Subject}s based on the configured value of the
 * {@link #isSessionStorageEnabled() sessionStorageEnabled} boolean property ({@code true} by default).
 *
 * @since 1.2
 */
public class DefaultSessionStorageEvaluator implements SessionStorageEvaluator {

    /**
     * Global policy determining if Subject sessions may be used to persist Subject state.
     */
    private boolean sessionStorageEnabled = true;

    /**
     * Returns the value of {@link #isSessionStorageEnabled()} and ignores the {@code Subject} argument.
     *
     * @param subject the {@code Subject} for which session state persistence may be enabled
     * @return the value of {@link #isSessionStorageEnabled()} and ignores the {@code Subject} argument.
     */
    public boolean isSessionStorageEnabled(Subject subject) {
        return isSessionStorageEnabled();
    }

    /**
     * Returns {@code true} if any Subject's {@code Session} may be used to persist that {@code Subject}'s state,
     * {@code false} otherwise.  The default value is {@code true}.
     * <p/>
     * <b>N.B.</b> This is a global configuration setting; setting this value to {@code false} will disable sessions
     * being used to persist Subject state for <em>all</em> Subjects.  It should typically only be set to {@code false}
     * for 100% stateless applications (e.g. when sessions aren't used or when remote clients authenticate on every
     * request).
     *
     * @return {@code true} if any Subject's {@code Session} may be used to persist that {@code Subject}'s state,
     *         {@code false} otherwise.
     */
    public boolean isSessionStorageEnabled() {
        return sessionStorageEnabled;
    }

    /**
     * Sets if any Subject's {@code Session} may be used to persist that {@code Subject}'s state.  The
     * default value is {@code true}.
     * <p/>
     * <b>N.B.</b> This is a global configuration setting; setting this value to {@code false} will disable sessions
     * being used to persist Subject state for <em>all</em> Subjects.  It should typically only be set to {@code false}
     * for 100% stateless applications (e.g. when sessions aren't used or when remote clients authenticate on every
     * request).
     *
     * @param sessionStorageEnabled if any Subject's {@code Session} may be used to persist that {@code Subject}'s state.
     */
    public void setSessionStorageEnabled(boolean sessionStorageEnabled) {
        this.sessionStorageEnabled = sessionStorageEnabled;
    }
}
