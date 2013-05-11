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
 * Exception thrown when attempting to interact with the system under a session that has been
 * stopped.  A session may be stopped in any number of ways, most commonly due to explicit
 * stopping (e.g. from logging out), or due to expiration.
 *
 * @since 0.1
 */
public class StoppedSessionException extends InvalidSessionException {

    /**
     * Creates a new StoppedSessionException.
     */
    public StoppedSessionException() {
        super();
    }

    /**
     * Constructs a new StoppedSessionException.
     *
     * @param message the reason for the exception
     */
    public StoppedSessionException(String message) {
        super(message);
    }

    /**
     * Constructs a new StoppedSessionException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public StoppedSessionException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new StoppedSessionException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public StoppedSessionException(String message, Throwable cause) {
        super(message, cause);
    }

}
