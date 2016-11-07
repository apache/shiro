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
package org.apache.shiro.util;

import org.apache.shiro.subject.PrincipalCollection;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Static helper class for use dealing with Collections.
 *
 * @since 0.9
 */
public class CollectionUtils {

    //TODO - complete JavaDoc

    public static <E> Set<E> asSet(E... elements) {
        if (elements == null || elements.length == 0) {
            return Collections.emptySet();
        }

        if (elements.length == 1) {
            return Collections.singleton(elements[0]);
        }

        LinkedHashSet<E> set = new LinkedHashSet<E>(elements.length * 4 / 3 + 1);
        Collections.addAll(set, elements);
        return set;
    }

    /**
     * Returns {@code true} if the specified {@code Collection} is {@code null} or {@link Collection#isEmpty empty},
     * {@code false} otherwise.
     *
     * @param c the collection to check
     * @return {@code true} if the specified {@code Collection} is {@code null} or {@link Collection#isEmpty empty},
     *         {@code false} otherwise.
     * @since 1.0
     */
    public static boolean isEmpty(Collection c) {
        return c == null || c.isEmpty();
    }

    /**
     * Returns {@code true} if the specified {@code Map} is {@code null} or {@link Map#isEmpty empty},
     * {@code false} otherwise.
     *
     * @param m the {@code Map} to check
     * @return {@code true} if the specified {@code Map} is {@code null} or {@link Map#isEmpty empty},
     *         {@code false} otherwise.
     * @since 1.0
     */
    public static boolean isEmpty(Map m) {
        return m == null || m.isEmpty();
    }

    /**
     * Returns the size of the specified collection or {@code 0} if the collection is {@code null}.
     *
     * @param c the collection to check
     * @return the size of the specified collection or {@code 0} if the collection is {@code null}.
     * @since 1.2
     */
    public static int size(Collection c) {
        return c != null ? c.size() : 0;
    }

    /**
     * Returns the size of the specified map or {@code 0} if the map is {@code null}.
     *
     * @param m the map to check
     * @return the size of the specified map or {@code 0} if the map is {@code null}.
     * @since 1.2
     */
    public static int size(Map m) {
        return m != null ? m.size() : 0;
    }


    /**
     * Returns {@code true} if the specified {@code PrincipalCollection} is {@code null} or
     * {@link PrincipalCollection#isEmpty empty}, {@code false} otherwise.
     *
     * @param principals the principals to check.
     * @return {@code true} if the specified {@code PrincipalCollection} is {@code null} or
     *         {@link PrincipalCollection#isEmpty empty}, {@code false} otherwise.
     * @since 1.0
     * @deprecated Use PrincipalCollection.isEmpty() directly.
     */
    @Deprecated
    public static boolean isEmpty(PrincipalCollection principals) {
        return principals == null || principals.isEmpty();
    }

    public static <E> List<E> asList(E... elements) {
        if (elements == null || elements.length == 0) {
            return Collections.emptyList();
        }

        // Integer overflow does not occur when a large array is passed in because the list array already exists
        return Arrays.asList(elements);
    }

    /*public static <E> Deque<E> asDeque(E... elements) {
        if (elements == null || elements.length == 0) {
            return new ArrayDeque<E>();
        }
        // Avoid integer overflow when a large array is passed in
        int capacity = computeListCapacity(elements.length);
        ArrayDeque<E> deque = new ArrayDeque<E>(capacity);
        Collections.addAll(deque, elements);
        return deque;
    }*/

    static int computeListCapacity(int arraySize) {
        return (int) Math.min(5L + arraySize + (arraySize / 10), Integer.MAX_VALUE);
    }
}
