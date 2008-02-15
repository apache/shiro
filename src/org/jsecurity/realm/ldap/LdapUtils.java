/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapContext;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility class providing static methods to make working with LDAP
 * easier.
 *
 * @since 0.2
 * @author Jeremy Haile
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


    /**
     * Helper method used to retrieve all attribute values from a particular context attribute.
     * @param attr the LDAP attribute.
     * @return the values of the attribute.
     * @throws javax.naming.NamingException if there is an LDAP error while reading the values.
     */
    public static Collection<String> getAllAttributeValues( Attribute attr ) throws NamingException {
        Set<String> values = new HashSet<String>();
        for ( NamingEnumeration e = attr.getAll(); e.hasMore(); ) {
            String value = (String)e.next();
            values.add( value );
        }
        return values;
    }


}
