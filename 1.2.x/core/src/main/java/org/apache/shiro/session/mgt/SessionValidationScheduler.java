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
 * Interface that should be implemented by classes that can control validating sessions on a regular
 * basis.  This interface is used as a delegate for session validation by the {@link org.apache.shiro.session.mgt.DefaultSessionManager}
 *
 * @see org.apache.shiro.session.mgt.DefaultSessionManager#setSessionValidationScheduler(SessionValidationScheduler)
 * @since 0.1
 */
public interface SessionValidationScheduler {

    /**
     * Returns <code>true</code> if this Scheduler is enabled and ready to begin validation at the appropriate time,
     * <code>false</code> otherwise.
     * <p/>
     * It does <em>not</em> indicate if the validation is actually executing at that instant - only that it is prepared
     * to do so at the appropriate time.
     *
     * @return <code>true</code> if this Scheduler is enabled and ready to begin validation at the appropriate time,
     * <code>false</code> otherwise.
     */
    boolean isEnabled();

    /**
     * Enables the session validation job.
     */
    void enableSessionValidation();

    /**
     * Disables the session validation job.
     */
    void disableSessionValidation();

}