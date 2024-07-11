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

import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.util.CollectionUtils;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.HashSet;
import java.util.Objects;


/**
 * An immutable implementation of the {@link PrincipalCollection} interface that tracks principals internally
 * by storing them in a {@link LinkedHashMap} of {@link LinkedHashSet}s, preserving the order of realms and the order
 * of principals per realm and all wrapped to become unmodifiable.
 * <p>
 * The first principal of the first non-empty realm is considered the primary principal of this collection.
 */
@SuppressWarnings("unchecked")
public final class ImmutablePrincipalCollection implements PrincipalCollection {

    /**
     * Shared empty instance to avoid per-instance allocation overhead.
     */
    public static final ImmutablePrincipalCollection EMPTY = empty();

    // Serialization reminder:
    // You _MUST_ change this number if you introduce a change to this class
    // that is NOT serialization backwards compatible.  Serialization-compatible
    // changes do not require a change to this number.  If you need to generate
    // a new number in this case, use the JDK's 'serialver' program to generate it.
    private static final long serialVersionUID = 8095033991024104940L;

    // Set of principals per realm
    private final Map<String, Set<Object>> realmPrincipals;

    // Cached toString() result, as this can be printed many times in logging. While this is formally a mutable
    // variable, its state is not visible to callers of this class.
    private transient String cachedToString;

    /**
     * This private constructor does not copy the argument collections, nor does it ensure immutability. The factory
     * methods do that, and we just store the collections here to avoid double copying.
     */
    private ImmutablePrincipalCollection(Map<String, Set<Object>> realmPrincipals) {
        if (realmPrincipals == null) {
            throw new IllegalArgumentException("realmPrincipals argument cannot be null.");
        }
        this.realmPrincipals = realmPrincipals;
    }

    // order-preserving variant of Set.copyOf()
    private static <T> Set<T> copySetShallow(Collection<? extends T> set) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(set));
    }

    // order-preserving variant of Map.copyOf()
    private static <K, V> Map<K, V> copyMapShallow(Map<? extends K, ? extends V> map) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(map));
    }

    /**
     * Creates a new, empty {@code ImmutablePrincipalCollection} instance.
     *
     * @return the new instance
     */
    public static ImmutablePrincipalCollection empty() {
        return new ImmutablePrincipalCollection(Collections.emptyMap());
    }

    /**
     * Creates a new {@code ImmutablePrincipalCollection} instance with the specified principals all
     * belonging to the same realm.
     *
     * @param principals the principals to add
     * @param realmName the name of the realm to add the principals to
     * @return the new instance
     */
    public static ImmutablePrincipalCollection ofSingleRealm(Collection<?> principals, String realmName) {
        if (principals.isEmpty()) {
            return empty();
        } else {
            return new ImmutablePrincipalCollection(Collections.singletonMap(realmName, copySetShallow(principals)));
        }
    }

    /**
     * Creates a new {@code ImmutablePrincipalCollection} instance with the specified single principal
     * for a single realm.
     *
     * @param principal the principal to add
     * @param realmName the name of the realm to add the principal to
     * @return the new instance
     */
    public static ImmutablePrincipalCollection ofSinglePrincipal(Object principal, String realmName) {
        return new ImmutablePrincipalCollection(Collections.singletonMap(realmName, Set.of(principal)));
    }

    /**
     * Creates a new {@code ImmutablePrincipalCollection} instance with the realms and principals from another
     * collection added in iteration order.
     *
     * @param original the original collection to copy
     * @return the new instance
     */
    public static ImmutablePrincipalCollection copyOf(PrincipalCollection original) {
        if (original instanceof ImmutablePrincipalCollection) {
            return (ImmutablePrincipalCollection) original;
        }
        return new Builder().addPrincipals(original).build();
    }

    @Override
    public Object getPrimaryPrincipal() {
        Iterator<?> iterator = iterator();
        return iterator.hasNext() ? iterator.next() : null;
    }

    @Override
    public <T> T oneByType(Class<T> type) {
        for (Set<?> set : realmPrincipals.values()) {
            for (Object principal : set) {
                if (type.isAssignableFrom(principal.getClass())) {
                    return (T) principal;
                }
            }
        }
        return null;
    }

    @Override
    public <T> Set<T> byType(Class<T> type) {
        Set<T> typed = new LinkedHashSet<>();
        for (Set<?> set : realmPrincipals.values()) {
            for (Object principal : set) {
                if (type.isAssignableFrom(principal.getClass())) {
                    typed.add((T) principal);
                }
            }
        }
        return Set.copyOf(typed);
    }

    @Override
    public List<?> asList() {
        return List.copyOf(asSet());
    }

    @Override
    public Set<?> asSet() {
        Set<Object> result = new HashSet<>();
        for (Set<?> set : realmPrincipals.values()) {
            result.addAll(set);
        }
        return copySetShallow(result);
    }

    @Override
    public Set<?> fromRealm(String realmName) {
        Set<?> principals = realmPrincipals.get(realmName);
        return principals != null ? principals : Collections.emptySet();
    }

    @Override
    public Set<String> getRealmNames() {
        return realmPrincipals.keySet();
    }

    @Override
    public boolean isEmpty() {
        for (Set<?> principals : realmPrincipals.values()) {
            if (!principals.isEmpty()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public Iterator<?> iterator() {
        return asSet().iterator();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof ImmutablePrincipalCollection) {
            ImmutablePrincipalCollection other = (ImmutablePrincipalCollection) o;
            return Objects.equals(this.realmPrincipals, other.realmPrincipals);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return realmPrincipals.hashCode();
    }

    @Override
    public String toString() {
        if (this.cachedToString == null) {
            Set<?> principals = asSet();
            if (!CollectionUtils.isEmpty(principals)) {
                this.cachedToString = StringUtils.toString(principals.toArray());
            } else {
                this.cachedToString = "empty";
            }
        }
        return this.cachedToString;
    }

    /**
     * Builder to create new {@link ImmutablePrincipalCollection} instances for more complex cases than a single realm.
     */
    public static final class Builder {

        private final Map<String, Set<Object>> realmPrincipals = new LinkedHashMap<>();

        /**
         * Returns the map of realm names to principal sets.
         *
         * @return the map-of-sets of principals for all realms
         */
        public Map<String, Set<Object>> getPrincipalsForAllRealms() {
            return realmPrincipals;
        }

        /**
         * Returns the set of principals for the specified realm. If the realm does not yet exist in this builder, it is
         * added to the end of the list of realms.
         *
         * @param realmName the realm to get the set of principals for
         * @return the set of principals for that realm
         */
        public Set<Object> getPrincipalsForRealm(String realmName) {
            if (realmName == null) {
                throw new NullPointerException("realmName argument cannot be null.");
            }
            return realmPrincipals.computeIfAbsent(realmName, (_key) -> new LinkedHashSet<>());
        }

        /**
         * Adds a single principal to a realm. The principal is added to the end of the list of principals for that
         * realm. If the realm does not yet exist in this builder, it is added to the end of the list of realms.
         *
         * @param principal the principal to add
         * @param realmName the realm to add the principal to
         * @return this
         */
        public Builder addPrincipal(Object principal, String realmName) {
            if (principal == null) {
                throw new NullPointerException("principal argument cannot be null.");
            }
            if (realmName == null) {
                throw new NullPointerException("realmName argument cannot be null.");
            }
            getPrincipalsForRealm(realmName).add(principal);
            return this;
        }

        /**
         * Adds a collection of principals to a single realm. The principals are stored in the iteration order of the
         * argument collection, appended to the end of the principals already present for that realm. If the realm does
         * not yet exist in this builder, it is added to the end of the list of realms.
         *
         * @param principals the principals to add
         * @param realmName the name of the realm to add the principals to
         * @return this
         */
        public Builder addPrincipals(Collection<?> principals, String realmName) {
            if (principals == null) {
                throw new NullPointerException("principals argument cannot be null.");
            }
            for (Object principal : principals) {
                addPrincipal(principal, realmName);
            }
            return this;
        }

        /**
         * Adds all principals from the specified {@link PrincipalCollection} to this builder. The order of realms,
         * as well as the order of principals within each realm, is preserved.
         *
         * @param principals the principals to add
         * @return this
         */
        public Builder addPrincipals(PrincipalCollection principals) {
            if (principals == null) {
                throw new NullPointerException("principals argument cannot be null.");
            }
            for (String realmName : principals.getRealmNames()) {
                addPrincipals(principals.fromRealm(realmName), realmName);
            }
            return this;
        }

        /**
         * Builds an {@link ImmutablePrincipalCollection} from the current state of this builder.
         *
         * @return the finished principal collection
         */
        public ImmutablePrincipalCollection build() {
            Map<String, Set<Object>> copy = new LinkedHashMap<>();
            for (Map.Entry<String, Set<Object>> entry : realmPrincipals.entrySet()) {
                if (!entry.getValue().isEmpty()) {
                    copy.put(entry.getKey(), copySetShallow(entry.getValue()));
                }
            }
            return new ImmutablePrincipalCollection(copyMapShallow(copy));
        }

    }

}
