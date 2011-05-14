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
package org.apache.shiro.subject;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * A collection of all principals associated with a corresponding {@link Subject Subject}.  A <em>principal</em> is
 * just a security term for an identifying attribute, such as a username or user id or social security number or
 * anything else that can be considered an 'identifying' attribute for a {@code Subject}.
 * <p/>
 * A PrincipalCollection organizes its internal principals based on the {@code Realm} where they came from when the
 * Subject was first created.  To obtain the principal(s) for a specific Realm, see the {@link #fromRealm} method.  You
 * can also see which realms contributed to this collection via the {@link #getRealmNames() getRealmNames()} method.
 *
 * @see #getPrimaryPrincipal()
 * @see #fromRealm(String realmName)
 * @see #getRealmNames()
 * @since 0.9
 */
public interface PrincipalCollection extends Iterable, Serializable {

    /**
     * Returns the primary principal used application-wide to uniquely identify the owning account/Subject.
     * <p/>
     * The value is usually always a uniquely identifying attribute specific to the data source that retrieved the
     * account data.  Some examples:
     * <ul>
     * <li>a {@link java.util.UUID UUID}</li>
     * <li>a {@code long} value such as a surrogate primary key in a relational database</li>
     * <li>an LDAP UUID or static DN</li>
     * <li>a String username unique across all user accounts</li>
     * </ul>
     * <h3>Multi-Realm Applications</h3>
     * In a single-{@code Realm} application, typically there is only ever one unique principal to retain and that
     * is the value returned from this method.  However, in a multi-{@code Realm} application, where the
     * {@code PrincipalCollection} might retain principals across more than one realm, the value returned from this
     * method should be the single principal that uniquely identifies the subject for the entire application.
     * <p/>
     * That value is of course application specific, but most applications will typically choose one of the primary
     * principals from one of the {@code Realm}s.
     * <p/>
     * Shiro's default implementations of this interface make this
     * assumption by usually simply returning {@link #iterator()}.{@link java.util.Iterator#next() next()}, which just
     * returns the first returned principal obtained from the first consulted/configured {@code Realm} during the
     * authentication attempt.  This means in a multi-{@code Realm} application, {@code Realm} configuration order
     * matters if you want to retain this default heuristic.
     * <p/>
     * If this heuristic is not sufficient, most Shiro end-users will need to implement a custom
     * {@link org.apache.shiro.authc.pam.AuthenticationStrategy}.  An {@code AuthenticationStrategy} has exact control
     * over the {@link PrincipalCollection} returned at the end of an authentication attempt via the
     * <code>AuthenticationStrategy#{@link org.apache.shiro.authc.pam.AuthenticationStrategy#afterAllAttempts(org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.authc.AuthenticationInfo) afterAllAttempts}</code>
     * implementation.
     *
     * @return the primary principal used to uniquely identify the owning account/Subject
     * @since 1.0
     */
    Object getPrimaryPrincipal();

    /**
     * Returns the first discovered principal assignable from the specified type, or {@code null} if there are none
     * of the specified type.
     * <p/>
     * Note that this will return {@code null} if the 'owning' subject has not yet logged in.
     *
     * @param type the type of the principal that should be returned.
     * @return a principal of the specified type or {@code null} if there isn't one of the specified type.
     */
    <T> T oneByType(Class<T> type);

    /**
     * Returns all principals assignable from the specified type, or an empty Collection if no principals of that
     * type are contained.
     * <p/>
     * Note that this will return an empty Collection if the 'owning' subject has not yet logged in.
     *
     * @param type the type of the principals that should be returned.
     * @return a Collection of principals that are assignable from the specified type, or
     *         an empty Collection if no principals of this type are associated.
     */
    <T> Collection<T> byType(Class<T> type);

    /**
     * Returns a single Subject's principals retrieved from all configured Realms as a List, or an empty List if
     * there are not any principals.
     * <p/>
     * Note that this will return an empty List if the 'owning' subject has not yet logged in.
     *
     * @return a single Subject's principals retrieved from all configured Realms as a List.
     */
    List asList();

    /**
     * Returns a single Subject's principals retrieved from all configured Realms as a Set, or an empty Set if there
     * are not any principals.
     * <p/>
     * Note that this will return an empty Set if the 'owning' subject has not yet logged in.
     *
     * @return a single Subject's principals retrieved from all configured Realms as a Set.
     */
    Set asSet();

    /**
     * Returns a single Subject's principals retrieved from the specified Realm <em>only</em> as a Collection, or an empty
     * Collection if there are not any principals from that realm.
     * <p/>
     * Note that this will return an empty Collection if the 'owning' subject has not yet logged in.
     *
     * @param realmName the name of the Realm from which the principals were retrieved.
     * @return the Subject's principals from the specified Realm only as a Collection or an empty Collection if there
     *         are not any principals from that realm.
     */
    Collection fromRealm(String realmName);

    /**
     * Returns the realm names that this collection has principals for.
     *
     * @return the names of realms that this collection has one or more principals for.
     */
    Set<String> getRealmNames();

    /**
     * Returns {@code true} if this collection is empty, {@code false} otherwise.
     *
     * @return {@code true} if this collection is empty, {@code false} otherwise.
     */
    boolean isEmpty();
}
