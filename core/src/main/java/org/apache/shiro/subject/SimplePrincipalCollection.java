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

import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.StringUtils;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;


/**
 * A simple implementation of the {@link MutablePrincipalCollection} interface that tracks principals internally
 * by storing them in a {@link LinkedHashMap}.
 *
 * @since 0.9
 */
@SuppressWarnings({"unchecked"})
public class SimplePrincipalCollection implements MutablePrincipalCollection {

    // Serialization reminder:
    // You _MUST_ change this number if you introduce a change to this class
    // that is NOT serialization backwards compatible.  Serialization-compatible
    // changes do not require a change to this number.  If you need to generate
    // a new number in this case, use the JDK's 'serialver' program to generate it.
    private static final long serialVersionUID = -6305224034025797558L;

    //TODO - complete JavaDoc

    private Map<String, Set> realmPrincipals;

    private transient String cachedToString; //cached toString() result, as this can be printed many times in logging

    public SimplePrincipalCollection() {
    }

    public SimplePrincipalCollection(Object principal, String realmName) {
        if (principal instanceof Collection) {
            addAll((Collection) principal, realmName);
        } else {
            add(principal, realmName);
        }
    }

    public SimplePrincipalCollection(Collection principals, String realmName) {
        addAll(principals, realmName);
    }

    public SimplePrincipalCollection(PrincipalCollection principals) {
        addAll(principals);
    }

    protected Collection getPrincipalsLazy(String realmName) {
        if (realmPrincipals == null) {
            realmPrincipals = new LinkedHashMap<String, Set>();
        }
        Set principals = realmPrincipals.get(realmName);
        if (principals == null) {
            principals = new LinkedHashSet();
            realmPrincipals.put(realmName, principals);
        }
        return principals;
    }

    /**
     * Returns the first available principal from any of the {@code Realm} principals, or {@code null} if there are
     * no principals yet.
     * <p/>
     * The 'first available principal' is interpreted as the principal that would be returned by
     * <code>{@link #iterator() iterator()}.{@link java.util.Iterator#next() next()}.</code>
     *
     * @inheritDoc
     */
    public Object getPrimaryPrincipal() {
        if (isEmpty()) {
            return null;
        }
        return iterator().next();
    }

    public void add(Object principal, String realmName) {
        if (realmName == null) {
            throw new NullPointerException("realmName argument cannot be null.");
        }
        if (principal == null) {
            throw new NullPointerException("principal argument cannot be null.");
        }
        this.cachedToString = null;
        getPrincipalsLazy(realmName).add(principal);
    }

    public void addAll(Collection principals, String realmName) {
        if (realmName == null) {
            throw new NullPointerException("realmName argument cannot be null.");
        }
        if (principals == null) {
            throw new NullPointerException("principals argument cannot be null.");
        }
        if (principals.isEmpty()) {
            throw new IllegalArgumentException("principals argument cannot be an empty collection.");
        }
        this.cachedToString = null;
        getPrincipalsLazy(realmName).addAll(principals);
    }

    public void addAll(PrincipalCollection principals) {
        if (principals.getRealmNames() != null) {
            for (String realmName : principals.getRealmNames()) {
                for (Object principal : principals.fromRealm(realmName)) {
                    add(principal, realmName);
                }
            }
        }
    }

    public <T> T oneByType(Class<T> type) {
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return null;
        }
        Collection<Set> values = realmPrincipals.values();
        for (Set set : values) {
            for (Object o : set) {
                if (type.isAssignableFrom(o.getClass())) {
                    return (T) o;
                }
            }
        }
        return null;
    }

    public <T> Collection<T> byType(Class<T> type) {
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        Set<T> typed = new LinkedHashSet<T>();
        Collection<Set> values = realmPrincipals.values();
        for (Set set : values) {
            for (Object o : set) {
                if (type.isAssignableFrom(o.getClass())) {
                    typed.add((T) o);
                }
            }
        }
        if (typed.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(typed);
    }

    public List asList() {
        Set all = asSet();
        if (all.isEmpty()) {
            return Collections.EMPTY_LIST;
        }
        return Collections.unmodifiableList(new ArrayList(all));
    }

    public Set asSet() {
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        Set aggregated = new LinkedHashSet();
        Collection<Set> values = realmPrincipals.values();
        for (Set set : values) {
            aggregated.addAll(set);
        }
        if (aggregated.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(aggregated);
    }

    public Collection fromRealm(String realmName) {
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        Set principals = realmPrincipals.get(realmName);
        if (principals == null || principals.isEmpty()) {
            principals = Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(principals);
    }

    public Set<String> getRealmNames() {
        if (realmPrincipals == null) {
            return null;
        } else {
            return realmPrincipals.keySet();
        }
    }

    public boolean isEmpty() {
        return realmPrincipals == null || realmPrincipals.isEmpty();
    }

    public void clear() {
        this.cachedToString = null;
        if (realmPrincipals != null) {
            realmPrincipals.clear();
            realmPrincipals = null;
        }
    }

    public Iterator iterator() {
        return asSet().iterator();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SimplePrincipalCollection) {
            SimplePrincipalCollection other = (SimplePrincipalCollection) o;
            return this.realmPrincipals != null ? this.realmPrincipals.equals(other.realmPrincipals) : other.realmPrincipals == null;
        }
        return false;
    }

    public int hashCode() {
        if (this.realmPrincipals != null && !realmPrincipals.isEmpty()) {
            return realmPrincipals.hashCode();
        }
        return super.hashCode();
    }

    /**
     * Returns a simple string representation suitable for printing.
     *
     * @return a simple string representation suitable for printing.
     * @since 1.0
     */
    public String toString() {
        if (this.cachedToString == null) {
            Set<Object> principals = asSet();
            if (!CollectionUtils.isEmpty(principals)) {
                this.cachedToString = StringUtils.toString(principals.toArray());
            } else {
                this.cachedToString = "empty";
            }
        }
        return this.cachedToString;
    }


    /**
     * Serialization write support.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serialization changes!!!
     * (use the JDK 'serialver' program for this)
     *
     * @param out output stream provided by Java serialization
     * @throws IOException if there is a stream error
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        boolean principalsExist = !CollectionUtils.isEmpty(realmPrincipals);
        out.writeBoolean(principalsExist);
        if (principalsExist) {
            out.writeObject(realmPrincipals);
        }
    }

    /**
     * Serialization read support - reads in the Map principals collection if it exists in the
     * input stream.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serialization changes!!!
     * (use the JDK 'serialver' program for this)
     *
     * @param in input stream provided by
     * @throws IOException            if there is an input/output problem
     * @throws ClassNotFoundException if the underlying Map implementation class is not available to the classloader.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        boolean principalsExist = in.readBoolean();
        if (principalsExist) {
            this.realmPrincipals = (Map<String, Set>) in.readObject();
        }
    }
}
