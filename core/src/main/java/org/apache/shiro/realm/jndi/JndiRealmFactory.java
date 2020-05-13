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
package org.apache.shiro.realm.jndi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.shiro.jndi.JndiLocator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.RealmFactory;
import org.apache.shiro.lang.util.StringUtils;


/**
 * Looks up one or more Realm instances from JNDI using specified {@link #setJndiNames jndiNames}.
 *
 * <p>This is primarily provided to support Realm instances configured in JEE and EJB environments, but will
 * work in any environment where {@link Realm Realm} instances are bound in JNDI instead of using
 * programmatic or text-based configuration.
 *
 * @since 0.9
 */
public class JndiRealmFactory extends JndiLocator implements RealmFactory {

    Collection<String> jndiNames = null;

    /**
     * Returns the JNDI names that will be used to look up Realm(s) from JNDI.
     *
     * @return the JNDI names that will be used to look up Realm(s) from JNDI.
     * @see #setJndiNames(String)
     * @see #setJndiNames(Collection)
     */
    public Collection<String> getJndiNames() {
        return jndiNames;
    }

    /**
     * Sets the JNDI names that will be used to look up Realm(s) from JNDI.
     * <p/>
     * The order of the collection determines the order that the Realms will be returned to the SecurityManager.
     * <p/>
     * If you find it easier to specify these names as a comma-delmited string, you may use the
     * {@link #setJndiNames(String)} method instead.
     *
     * @param jndiNames the JNDI names that will be used to look up Realm(s) from JNDI.
     * @see #setJndiNames(String)
     */
    public void setJndiNames(Collection<String> jndiNames) {
        this.jndiNames = jndiNames;
    }

    /**
     * Specifies a comma-delimited list of JNDI names to lookup, each one corresponding to a jndi-bound
     * {@link Realm Realm}.  The Realms will be made available to the SecurityManager in the order
     * they are defined.
     *
     * @param commaDelimited a comma-delimited list of JNDI names, each representing the JNDI name used to
     *                       look up a corresponding jndi-bound Realm.
     * @throws IllegalStateException if the specified argument is null or the empty string.
     */
    public void setJndiNames(String commaDelimited) throws IllegalStateException {
        String arg = StringUtils.clean(commaDelimited);
        if (arg == null) {
            String msg = "One or more comma-delimited jndi names must be specified for the " +
                    getClass().getName() + " to locate Realms.";
            throw new IllegalStateException(msg);
        }
        String[] names = StringUtils.tokenizeToStringArray(arg, ",");
        setJndiNames(Arrays.asList(names));
    }

    /**
     * Performs the JNDI lookups for each specified {@link #getJndiNames() JNDI name} and returns all
     * discovered Realms in an ordered collection.
     *
     * <p>The returned Collection is in the same order as the specified
     * {@link #setJndiNames(java.util.Collection) jndiNames}
     *
     * @return an ordered collection of the {@link #setJndiNames(java.util.Collection) specified Realms} found in JNDI.
     * @throws IllegalStateException if any of the JNDI names fails to successfully look up a Realm instance.
     */
    public Collection<Realm> getRealms() throws IllegalStateException {
        Collection<String> jndiNames = getJndiNames();
        if (jndiNames == null || jndiNames.isEmpty()) {
            String msg = "One or more jndi names must be specified for the " +
                    getClass().getName() + " to locate Realms.";
            throw new IllegalStateException(msg);
        }
        List<Realm> realms = new ArrayList<Realm>(jndiNames.size());
        for (String name : jndiNames) {
            try {
                Realm realm = (Realm) lookup(name, Realm.class);
                realms.add(realm);
            } catch (Exception e) {
                throw new IllegalStateException("Unable to look up realm with jndi name '" + name + "'.", e);
            }
        }
        return realms.isEmpty() ? null : realms;
    }
}
