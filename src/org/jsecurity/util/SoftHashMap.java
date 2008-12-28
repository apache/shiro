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
package org.jsecurity.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.*;

/**
 * A <code><em>Soft</em>HashMap</code> is a memory-constrained map that stores its <em>values</em> in
 * {@link SoftReference SoftReference}s.  (Contrast this with the JDK's
 * {@link WeakHashMap WeakHashMap}, which uses weak references for its <em>keys</em>, which is of little value if you
 * want the cache to auto-resize itself based on memory constraints).
 * <p/>
 * Having the values wrapped by soft references allows the cache to automatically reduce its size based on memory
 * limitations and garbage collection.  This ensures that the cache will not cause memory leaks by holding hard
 * references to all of its values.
 * <p/>
 * This class is a generics-enabled Map based on initial ideas from Hienz Kabutz's and Sydney Redelinghuys's
 * <a href="http://www.javaspecialists.eu/archive/Issue015.html">publicly posted version</a>, with continued
 * modifications.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SoftHashMap<K, V> extends AbstractMap<K, V> {

    /**
     * The default value of the HARD_SIZE attribute, equal to 100.
     */
    private static final int DEFAULT_HARD_SIZE = 100;

    /**
     * The internal HashMap that will hold the SoftReference.
     */
    private final Map<K, SoftValue<V, K>> map = new HashMap<K, SoftValue<V, K>>();

    /**
     * The number of &quot;hard&quot; references to hold internally, that is, the number of instances to prevent
     * from being garbage collected automatically (unlike other soft references).
     */
    private final int HARD_SIZE;

    /**
     * The FIFO list of hard references (not to be garbage collected), order of last access.
     */
    private final LinkedList<V> hardCache = new LinkedList<V>();

    /**
     * Reference queue for cleared SoftReference objects.
     */
    private final ReferenceQueue<? super V> queue = new ReferenceQueue<V>();

    public SoftHashMap() {
        this(DEFAULT_HARD_SIZE);
    }

    public SoftHashMap(int hardSize) {
        HARD_SIZE = hardSize;
    }

    public V get(Object key) {

        V result = null;

        SoftValue<V, K> value = map.get(key);

        if (value != null) {
            //unwrap the 'real' value from the SoftReference
            result = value.get();
            if (result == null) {
                //The wrapped value was garbage collected, so remove this entry from the backing map:
                map.remove(key);
            } else {
                //Add this value to the beginning of the 'hard' reference queue (FIFO).
                hardCache.addFirst(result);

                //trim the hard ref queue if necessary:
                if (hardCache.size() > HARD_SIZE) {
                    hardCache.removeLast();
                }
            }
        }
        return result;
    }

    /**
     * We define our own subclass of SoftReference which contains
     * not only the value but also the key to make it easier to find
     * the entry in the HashMap after it's been garbage collected.
     */
    private static class SoftValue<V, K> extends SoftReference<V> {

        private final K key;

        /**
         * Constructs a new instance, wrapping the value, key, and queue, as
         * required by the superclass.
         *
         * @param value the map value
         * @param key   the map key
         * @param queue the soft reference queue to poll to determine if the entry had been reaped by the GC.
         */
        private SoftValue(V value, K key, ReferenceQueue<? super V> queue) {
            super(value, queue);
            this.key = key;
        }
    }

    /**
     * Traverses the ReferenceQueue and removes garbage-collected SoftValue objects from the backing map
     * by looking them up using the SoftValue.key data member.
     */
    private void processQueue() {
        SoftValue sv;
        while ((sv = (SoftValue) queue.poll()) != null) {
            map.remove(sv.key); // we can access private data!
        }
    }

    /**
     * Creates a new entry, but wraps the value in a SoftValue instance to enable auto garbage collection.
     */
    public V put(K key, V value) {
        processQueue(); // throw out garbage collected values first
        SoftValue<V, K> sv = new SoftValue<V, K>(value, key, queue);
        return map.put(key, sv).get();
    }

    public V remove(Object key) {
        processQueue(); // throw out garbage collected values first
        SoftValue<V, K> raw = map.remove(key);
        V removed = null;
        if (raw != null) {
            removed = raw.get();
        }
        return removed;
    }

    public void clear() {
        hardCache.clear();
        processQueue(); // throw out garbage collected values
        map.clear();
    }

    public int size() {
        processQueue(); // throw out garbage collected values first
        return map.size();
    }

    @SuppressWarnings({"unchecked"})
    public Set<Map.Entry<K, V>> entrySet() {
        processQueue(); // throw out garbage collected values first
        Set set = map.entrySet();
        return Collections.unmodifiableSet(set);
    }


}
