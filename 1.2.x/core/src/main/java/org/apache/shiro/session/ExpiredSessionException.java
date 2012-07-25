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
package org.apache.shiro.session;

/**
 * A special case of a StoppedSessionException.  An expired session is a session that has
 * stopped explicitly due to inactivity (i.e. time-out), as opposed to stopping due to log-out or
 * other reason.
 *
 * @since 0.1
 */
public class ExpiredSessionException extends StoppedSessionException {

    /**
     * Creates a new ExpiredSessionException.
     */
    public ExpiredSessionException() {
        super();
    }

    /**
     * Constructs a new ExpiredSessionException.
     *
     * @param message the reason for the exception
     */
    public ExpiredSessionException(String message) {
        super(message);
    }

    /**
     * Constructs a new ExpiredSessionException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredSessionException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExpiredSessionException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredSessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
