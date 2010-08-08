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
package org.apache.shiro.realm.ldap;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class providing static methods to make working with LDAP
 * easier.
 *
 * @since 0.2
 */
public final class LdapUtils {

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(LdapUtils.class);

    /**
     * Closes an LDAP context, logging any errors, but not throwing
     * an exception if there is a failure.
     *
     * @param ctx the LDAP context to close.
     */
    public static void closeContext(LdapContext ctx) {
        try {
            if (ctx != null) {
                ctx.close();
            }
        } catch (NamingException e) {
            log.error("Exception while closing LDAP context. ", e);
        }
    }

    /**
     * Helper method used to retrieve all attribute values from a particular context attribute.
     *
     * @param attr the LDAP attribute.
     * @return the values of the attribute.
     * @throws javax.naming.NamingException if there is an LDAP error while reading the values.
     */
    public static Collection<String> getAllAttributeValues(Attribute attr) throws NamingException {
        Set<String> values = new HashSet<String>();
        NamingEnumeration ne = null;
        try {
            ne = attr.getAll();
            while (ne.hasMore()) {
                String value = (String) ne.next();
                values.add(value);
            }
        } finally {
            closeEnumeration(ne);
        }

        return values;
    }

    //added based on SHIRO-127, per Emmanuel's comment [1]
    // [1] https://issues.apache.org/jira/browse/SHIRO-127?focusedCommentId=12891380&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#action_12891380

    public static void closeEnumeration(NamingEnumeration ne) {
        try {
            if (ne != null) {
                ne.close();
            }
        } catch (NamingException e) {
            log.error("Exception while closing NamingEnumeration: ", e);
        }
    }

}
