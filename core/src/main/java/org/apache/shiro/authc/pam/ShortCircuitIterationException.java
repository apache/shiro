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
package org.apache.shiro.authc.pam;

import org.apache.shiro.authc.AuthenticationException;


/**
 * Exception thrown during the authentication process using
 * {@link org.apache.shiro.authc.pam.FirstSuccessfulStrategy}, with 
 * <code>stopAfterFirstSuccess</code> set.  
 * This is a signal to short circuit the authentication from proceeding 
 * with subsequent {@link org.apache.shiro.realm.Realm Realm}s 
 * after a first successful authentication.
 *
 * @see org.apache.shiro.authc.pam.AuthenticationStrategy
 * @see org.apache.shiro.authc.pam.FirstSuccessfulStrategy
 * @since 1.4.1
 */
public class ShortCircuitIterationException extends AuthenticationException {

    /**
     * Creates a new ShortCircuitIterationException.
     */
    public ShortCircuitIterationException() {
        super();
    }

    /**
     * Constructs a new ShortCircuitIterationException.
     *
     * @param message the reason for the exception
     */
    public ShortCircuitIterationException(String message) {
        super(message);
    }

    /**
     * Constructs a new ShortCircuitIterationException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ShortCircuitIterationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ShortCircuitIterationException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ShortCircuitIterationException(String message, Throwable cause) {
        super(message, cause);
    }
}
