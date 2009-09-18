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
 * Note that by convention however, the 'first' principal returned from this collection is considered to be the
 * Subject's <em>primary</em> principal used by the application, usually a user ID or username, based on the
 * {@code Realm} implementation.  The 'first' principal is that which is returned by
 * {@link #asList() asList()}{@code .iterator().next()}.
 * <p/>
 * A PrincipalCollection organizes its internal principals based on the {@code Realm} where they came from when the
 * Subject was first created.  To obtain the principal(s) for a specific Realm, see the {@link #fromRealm} method.  You
 * can also see which realms contributed to this collection via the {@link #getRealmNames() getRealmNames()} method.
 *
 * @author Les Hazlewood
 * @see #fromRealm(String realmName)
 * @see #getRealmNames()
 * @since 0.9
 */
public interface PrincipalCollection extends Iterable, Serializable {

    /**
     * Returns a single principal assignable from the specified type, or {@code null} if there are none of the
     * specified type.
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
