/*
 * Copyright (C) 2005-2007 Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.realm.ldap;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * Interface that encapsulates the creation of <tt>LdapContext</tt> objects that are used by subclasses
 * of {@link AbstractLdapRealm} to query for authentication and authorization information of particular
 * users.
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public interface LdapContextFactory {

    /**
     * Creates (or retrieves from a pool) a <tt>LdapContext</tt> connection bound using the system account, or anonymously
     * if no system account is configured.
     * @return a <tt>LdapContext</tt> bound by the system account, or bound anonymously if no system account
     * is configured.
     * @throws javax.naming.NamingException if there is an error creating the context.
     */
    LdapContext getSystemLdapContext() throws NamingException;

    /**
     * Creates (or retrieves from a pool) a <tt>LdapContext</tt> connection bound using the username and password
     * specified.
     * @param username the username to use when creating the connection.
     * @param password the password to use when creating the connection.
     * @return a <tt>LdapContext</tt> bound using the given username and password.
     * @throws javax.naming.NamingException if there is an error creating the context.
     */
    LdapContext getLdapContext( String username, String password ) throws NamingException;

}
