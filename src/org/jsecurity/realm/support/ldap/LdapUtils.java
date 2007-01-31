package org.jsecurity.realm.support.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * Utility class providing static methods to make working with LDAP
 * easier.
 */
public class LdapUtils {

    /**
     * Commons logger.
     */
    private static final Log log = LogFactory.getLog(LdapUtils.class);

    /**
     *  Private constructor to prevent instantiation
     */
    private LdapUtils() {}

    /**
     * Closes an LDAP context, logging any errors, but not throwing 
     * an exception if there is a failure.
     * @param ctx the LDAP context to close.
     */
    public static void closeContext(LdapContext ctx) {
        try {
            if (ctx != null) {
                ctx.close();
            }
        } catch (NamingException e) {
            if( log.isErrorEnabled() ) {
                log.error("Exception while closing LDAP context. ", e);
            }
        }
    }


}
