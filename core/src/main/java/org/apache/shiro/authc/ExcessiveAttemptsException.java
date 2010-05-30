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
package org.apache.shiro.authc;

/**
 * Thrown when a system is configured to only allow a certain number of authentication attempts
 * over a period of time and the current session has failed to authenticate successfully within
 * that number.  The resulting action of such an exception is application-specific, but
 * most systems either temporarily or permanently lock that account to prevent further
 * attempts.
 *
 * @since 0.1
 */
public class ExcessiveAttemptsException extends AccountException {

    /**
     * Creates a new ExcessiveAttemptsException.
     */
    public ExcessiveAttemptsException() {
        super();
    }

    /**
     * Constructs a new ExcessiveAttemptsException.
     *
     * @param message the reason for the exception
     */
    public ExcessiveAttemptsException(String message) {
        super(message);
    }

    /**
     * Constructs a new ExcessiveAttemptsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExcessiveAttemptsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExcessiveAttemptsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ExcessiveAttemptsException(String message, Throwable cause) {
        super(message, cause);
    }
}
