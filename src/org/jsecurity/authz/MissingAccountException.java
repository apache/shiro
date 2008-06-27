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
package org.jsecurity.authz;

/**
 * An exception thrown when an Authorization operation is performed for a subject identity, but it is discovered
 * that there is no <tt>Account</tt> for that subject to perform authorization checks against.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class MissingAccountException extends AuthorizationException {

    public MissingAccountException() {
        super();
    }


    public MissingAccountException(String message) {
        super(message);
    }


    public MissingAccountException(Throwable cause) {
        super(cause);
    }


    public MissingAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}