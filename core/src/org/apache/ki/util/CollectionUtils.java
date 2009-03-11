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
package org.apache.ki.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Static helper class for use dealing with Arrays.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.9
 */
public class CollectionUtils {

    //TODO - complete JavaDoc

    /**
     * Simple method that just returns <code>Collections.EMPTY_SET</code>.
     * This exists to enable type-safe empty collections so other locations in Apache Ki code
     * do not need to worry about suppressing warnings.
     *
     * @param clazz the class of the collection type to return
     * @return an empty collection
     */
    @SuppressWarnings({"unchecked"})
    public static <E> Collection<E> emptyCollection(Class<E> clazz) {
        return Collections.EMPTY_SET;
    }

    @SuppressWarnings({"unchecked"})
    public static <E> Set<E> asSet(E... elements) {
        if (elements == null || elements.length == 0) {
            return Collections.EMPTY_SET;
        }
        LinkedHashSet<E> set = new LinkedHashSet<E>(elements.length * 4 / 3 + 1);
        Collections.addAll(set, elements);
        return set;
    }

    @SuppressWarnings({"unchecked"})
    public static <E> List<E> asList(E... elements) {
        if (elements == null || elements.length == 0) {
            return Collections.EMPTY_LIST;
        }
        // Avoid integer overflow when a large array is passed in
        int capacity = computeListCapacity(elements.length);
        ArrayList<E> list = new ArrayList<E>(capacity);
        Collections.addAll(list, elements);
        return list;
    }

    static int computeListCapacity(int arraySize) {
        return (int) Math.min(5L + arraySize + (arraySize / 10), Integer.MAX_VALUE);
    }
}
