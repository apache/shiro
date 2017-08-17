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

import org.apache.shiro.session.Session;

/**
 * Base abstract class of the {@link SessionManager SessionManager} interface, enabling configuration of an
 * application-wide {@link #getGlobalSessionTimeout() globalSessionTimeout}.  Default global session timeout is
 * {@code 30} minutes.
 *
 * @since 0.1
 */
//TODO - deprecate this class (see SHIRO-240):
//This is only here to make available a common attribute 'globalSessionTimeout' to subclasses, particularly to make it
//available to both AbstractNativeSessionManager and ServletContainerSessionManager subclass trees.  However, the
//ServletContainerSessionManager implementation does not use this value
//(see https://issues.apache.org/jira/browse/SHIRO-240 for why).  That means that only the Native session managers
//need a globalSessionTimeout property, making this class unnecessary.
public abstract class AbstractSessionManager implements SessionManager {

    protected static final long MILLIS_PER_SECOND = 1000;
    protected static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    protected static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;

    /**
     * Default main session timeout value, equal to {@code 30} minutes.
     */
    public static final long DEFAULT_GLOBAL_SESSION_TIMEOUT = 30 * MILLIS_PER_MINUTE;

    private long globalSessionTimeout = DEFAULT_GLOBAL_SESSION_TIMEOUT;

    public AbstractSessionManager() {
    }

    /**
     * Returns the system-wide default time in milliseconds that any session may remain idle before expiring. This
     * value is the main default for all sessions and may be overridden on a <em>per-session</em> basis by calling
     * {@code Subject.getSession().}{@link Session#setTimeout setTimeout(long)} if so desired.
     * <ul>
     * <li>A negative return value means sessions never expire.</li>
     * <li>A non-negative return value (0 or greater) means session timeout will occur as expected.</li>
     * </ul>
     * <p/>
     * Unless overridden via the {@link #setGlobalSessionTimeout} method, the default value is
     * {@link #DEFAULT_GLOBAL_SESSION_TIMEOUT}.
     *
     * @return the time in milliseconds that any session may remain idle before expiring.
     */
    public long getGlobalSessionTimeout() {
        return this.globalSessionTimeout;
    }

    /**
     * Sets the system-wide default time in milliseconds that any session may remain idle before expiring. This
     * value is the main default for all sessions and may be overridden on a <em>per-session</em> basis by calling
     * {@code Subject.getSession().}{@link Session#setTimeout setTimeout(long)} if so desired.
     * <p/>
     * <ul>
     * <li>A negative return value means sessions never expire.</li>
     * <li>A non-negative return value (0 or greater) means session timeout will occur as expected.</li>
     * </ul>
     * <p/>
     * Unless overridden by calling this method, the default value is {@link #DEFAULT_GLOBAL_SESSION_TIMEOUT}.
     *
     * @param globalSessionTimeout the time in milliseconds that any session may remain idle before expiring.
     */
    public void setGlobalSessionTimeout(long globalSessionTimeout) {
        this.globalSessionTimeout = globalSessionTimeout;
    }
}
