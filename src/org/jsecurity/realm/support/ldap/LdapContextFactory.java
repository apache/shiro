package org.jsecurity.realm.support.ldap;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * Interface that encapsulates the creation of <tt>LdapContext</tt> objects that are used by subclasses
 * of {@link AbstractLdapRealm} to query for authentication and authorization information of particular
 * users.
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
