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
 * Thrown during the authentication process when the system determines the submitted credential(s)
 * has expired and will not allow login.
 *
 * <p>This is most often used to alert a user that their credentials (e.g. password or
 * cryptography key) has expired and they should change the value.  In such systems, the component
 * invoking the authentication might catch this exception and redirect the user to an appropriate
 * view to allow them to update their password or other credentials mechanism.
 *
 * @since 0.1
 */
public class ExpiredCredentialsException extends CredentialsException {

    /**
     * Creates a new ExpiredCredentialsException.
     */
    public ExpiredCredentialsException() {
        super();
    }

    /**
     * Constructs a new ExpiredCredentialsException.
     *
     * @param message the reason for the exception
     */
    public ExpiredCredentialsException(String message) {
        super(message);
    }

    /**
     * Constructs a new ExpiredCredentialsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredCredentialsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new ExpiredCredentialsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
}
