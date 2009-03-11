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
package org.apache.ki.realm.ldap;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * Interface that encapsulates the creation of <tt>LdapContext</tt> objects that are used by subclasses
 * of {@link AbstractLdapRealm} to query for <tt>AuthenticationInfo</tt> security data (roles, permissions, etc) of particular
 * Subjects (users).
 *
 * @author Jeremy Haile
 * @since 0.2
 */
public interface LdapContextFactory {

    /**
     * Creates (or retrieves from a pool) a <tt>LdapContext</tt> connection bound using the system account, or anonymously
     * if no system account is configured.
     *
     * @return a <tt>LdapContext</tt> bound by the system account, or bound anonymously if no system account
     *         is configured.
     * @throws javax.naming.NamingException if there is an error creating the context.
     */
    LdapContext getSystemLdapContext() throws NamingException;

    /**
     * Creates (or retrieves from a pool) a <tt>LdapContext</tt> connection bound using the username and password
     * specified.
     *
     * @param username the username to use when creating the connection.
     * @param password the password to use when creating the connection.
     * @return a <tt>LdapContext</tt> bound using the given username and password.
     * @throws javax.naming.NamingException if there is an error creating the context.
     */
    LdapContext getLdapContext(String username, String password) throws NamingException;

}
