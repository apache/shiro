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
 * Exception thrown when the JSecurity framework encounters an {@link org.jsecurity.authc.Account Account} instance
 * during an authorization (access control) operation and it cannot perform the operation due to not knowing how to
 * interact with the specific account instance.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class UnsupportedAccountException extends AuthorizationException {

    public UnsupportedAccountException() {
        super();
    }

    public UnsupportedAccountException(String message) {
        super(message);
    }

    public UnsupportedAccountException(Throwable cause) {
        super(cause);
    }

    public UnsupportedAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}
