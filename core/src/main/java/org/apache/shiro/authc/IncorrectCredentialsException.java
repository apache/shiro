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
 * Thrown when attempting to authenticate with credential(s) that do not match the actual
 * credentials associated with the account principal.
 *
 * <p>For example, this exception might be thrown if a user's password is &quot;secret&quot; and
 * &quot;secrets&quot; was entered by mistake.
 *
 * <p>Whether or not an application wishes to let
 * the user know if they entered incorrect credentials is at the discretion of those
 * responsible for defining the view and what happens when this exception occurs.
 *
 * @since 0.1
 */
public class IncorrectCredentialsException extends CredentialsException {

    /**
     * Creates a new IncorrectCredentialsException.
     */
    public IncorrectCredentialsException() {
        super();
    }

    /**
     * Constructs a new IncorrectCredentialsException.
     *
     * @param message the reason for the exception
     */
    public IncorrectCredentialsException(String message) {
        super(message);
    }

    /**
     * Constructs a new IncorrectCredentialsException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public IncorrectCredentialsException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new IncorrectCredentialsException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public IncorrectCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

}
