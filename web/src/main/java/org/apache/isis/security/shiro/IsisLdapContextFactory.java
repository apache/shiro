/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.security.shiro;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import org.apache.shiro.realm.ldap.JndiLdapContextFactory;

/**
 * An extension of {@link JndiLdapContextFactory} that allows a different authentication mechanism
 * for system-level authentications (as used by authorization lookups, for example)
 * compared to regular authentication.
 * 
 * <p>
 * See {@link IsisLdapRealm} for typical configuration within <tt>shiro.ini</tt>.
 */
public class IsisLdapContextFactory extends JndiLdapContextFactory {

    private String systemAuthenticationMechanism;

    /**
     * HACK
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Override
    protected LdapContext createLdapContext(Hashtable env) throws NamingException {
        if(getSystemUsername() != null && getSystemUsername().equals(env.get(Context.SECURITY_PRINCIPAL))) {
            env.put(Context.SECURITY_AUTHENTICATION, getSystemAuthenticationMechanism());
        }
        return super.createLdapContext(env);
    }

    public String getSystemAuthenticationMechanism() {
        return systemAuthenticationMechanism != null? systemAuthenticationMechanism: getAuthenticationMechanism();
    }
    public void setSystemAuthenticationMechanism(String systemAuthenticationMechanism) {
        this.systemAuthenticationMechanism = systemAuthenticationMechanism;
    }
    
    
}
