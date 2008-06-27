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
package org.jsecurity.authc.event;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * Event triggered when an authentication attempt fails.  If an exception is thrown indicating
 * the attempt failure, it will be accessible via the {@link #getCause()} method so one
 * may determine why the authentication failed.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class FailedAuthenticationEvent extends AttemptedAuthenticationEvent {

    /**
     * The AuthenticationException that failed the attempt or <code>null</code> if the
     * attempt failed for another reason.
     */
    private AuthenticationException cause = null;

    /**
     * Constructs a FailedAuthenticationEvent in response to the failed attempt corresponding
     * to the submitted <code>token</code>.
     *
     * @param token the <code>token</code> submitted that resulted in an attempt failure.
     */
    public FailedAuthenticationEvent(AuthenticationToken token) {
        super(token);
    }

    /**
     * Constructs a FailedAuthenticationEvent in response to the failed attempt corresponding
     * to the submitted <code>token</code>, triggered by the specified <code>source</code>.
     *
     * @param token  the <code>token</code> submitted that resulted in an attempt failure.
     * @param source the component responsible for triggering the event.
     */
    public FailedAuthenticationEvent(AuthenticationToken token, Object source) {
        super(token, source);
    }

    /**
     * Constructs a FailedAuthenticationEvent in response to the failed attempt corresponding
     * to the submitted <code>token</code> which resulted in the specified <code>cause</code> exception.
     *
     * @param token the <code>token</code> submitted that resulted in an attempt failure.
     * @param cause the exception thrown as a result of the failed attempt.
     */
    public FailedAuthenticationEvent(AuthenticationToken token, AuthenticationException cause) {
        this(token);
        setCause(cause);
    }

    /**
     * Constructs a FailedAuthenticationEvent in response to the failed attempt corresponding
     * to the submitted <code>token</code>, resulting in the specified <code>cause</code> exception and
     * triggered by the specified <code>source</code>
     *
     * @param token  the <code>token</code> submitted that resulted in an attempt failure.
     * @param source the component responsible for triggering the event.
     * @param cause  the exception thrown as a result of the failed attempt.
     */
    public FailedAuthenticationEvent(AuthenticationToken token, Object source, AuthenticationException cause) {
        super(token, source);
        setCause(cause);
    }

    /**
     * Returns the <code>AuthenticationException</code> that caused the related authentication attempt to fail.
     *
     * @return the <code>AuthenticationException</code> that caused the related authentication attempt to fail.
     */
    public AuthenticationException getCause() {
        return this.cause;
    }

    /**
     * Utility method for subclasses to set the related <code>cause</code> for why the authentication attempt failed.
     *
     * @param cause the exception thrown as a result of the failed attempt.
     */
    protected void setCause(AuthenticationException cause) {
        if (cause == null) {
            String msg = "cause argument cannot be null";
            throw new IllegalArgumentException(msg);
        }
        this.cause = cause;
    }

}
