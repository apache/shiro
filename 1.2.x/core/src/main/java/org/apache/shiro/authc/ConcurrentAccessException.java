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
 * Thrown when an authentication attempt has been received for an account that has already been
 * authenticated (i.e. logged-in), and the system is configured to prevent such concurrent access.
 *
 * <p>This is useful when an application must ensure that only one person is logged-in to a single
 * account at any given time.
 *
 * <p>Sometimes account names and passwords are lazily given away
 * to many people for easy access to a system.  Such behavior is undesirable in systems where
 * users are accountable for their actions, such as in government applications, or when licensing
 * agreements must be maintained, such as those which only allow 1 user per paid license.
 *
 * <p>By disallowing concurrent access, such systems can ensure that each authenticated session
 * corresponds to one and only one user at any given time.
 *
 * @since 0.1
 */
public class ConcurrentAccessException extends AccountException {

    /**
     * Creates a new ConcurrentAccessException.
     */
    public ConcurrentAccessException() {
        super();
    }

    /**
     * Constructs a new ConcurrentAccessException.
     *
     * @param message the reason for the exception
     */
    public ConcurrentAccessException(String message) {
        super(message);
    }

    /**
     * Constructs a new ConcurrentAccessException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ConcurrentAccessException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ConcurrentAccessException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ConcurrentAccessException(String message, Throwable cause) {
        super(message, cause);
    }

}
