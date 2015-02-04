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
package org.apache.shiro.ldap;

import org.apache.shiro.dao.InvalidResourceUsageException;

/**
 * Exception thrown when a configured LDAP
 * <a href="http://download.oracle.com/javase/jndi/tutorial/ldap/security/auth.html">
 * Authentication Mechanism</a> is unsupported by the target LDAP server. (e.g. DIGEST-MD5, simple, etc)
 *
 * @since 1.2
 */
public class UnsupportedAuthenticationMechanismException extends InvalidResourceUsageException {

    public UnsupportedAuthenticationMechanismException(String message) {
        super(message);
    }

    public UnsupportedAuthenticationMechanismException(String message, Throwable cause) {
        super(message, cause);
    }
}
