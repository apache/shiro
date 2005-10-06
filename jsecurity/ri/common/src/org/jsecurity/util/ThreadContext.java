/*
 * Copyright (C) 2005 Les A. Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * A ThreadContext provides a means of binding and unbinding objects to the
 * current thread based on key/value pairs.
 *
 * <p>
 * An internal {@link java.util.HashMap} is used to maintain the key/value pairs
 * for each thread. If a Thread is pooled or reused, the internal map will not
 * be cleared upon thread reuse. It is the application's responsibility to bind
 * and remove values as necessary.
 *
 * <p>
 * If the desired behavior is to ensure that Thread data is not shared across
 * threads in a pooled or reusable Threaded environment, the application must
 * bind and remove any necessary values at the beginning and end of stack
 * execution, respectively.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
@SuppressWarnings(value = { "unchecked", "unsafe" })
public abstract class ThreadContext {

    protected static final Log logger = LogFactory.getLog(ThreadContext.class);

    protected static ThreadLocal<Map<Object, Object>> resources =
        new ThreadLocal<Map<Object, Object>>() {
            protected Map<Object, Object> initialValue() {
                return new HashMap<Object, Object>();
            }
        };

    protected ThreadContext() {
    }

    /**
     * Returns the ThreadLocal Map. This Map is used internally to bind objects
     * to the current thread by storing each object under a unique key.
     *
     * @return the map of bound resources
     */
    protected static Map<Object, Object> getResources() {
        return resources.get();
    }

    /**
     * Returns the object for the specified <code>key</code> that is bound to
     * the current thread.
     *
     * @param key
     *            the key that identifies the value to return
     * @return the object keyed by <code>key</code> or <code>null</code> if
     *         no value exists for the specified <code>key</code>
     */
    public static Object get(Object key) {
        if (logger.isTraceEnabled()) {
            String msg = "get() - in thread [" + Thread.currentThread().getName() + "]";
            logger.trace(msg);
        }
        Object value = getResources().get(key);
        if ((value != null) && logger.isTraceEnabled()) {
            String msg = "Retrieved value of type [" + value.getClass() + "] for key [" + key
                    + "] " + "bound to thread [" + Thread.currentThread().getName() + "]";
            logger.trace(msg);
        }
        return value;
    }

    /**
     * Binds <code>value</code> for the given <code>key</code> to the
     * current thread.
     *
     * @param key
     *            The key with which to identify the <code>value</code>.
     * @param value
     *            The value to bind to the thread.
     * @throws IllegalArgumentException
     *             if either <code>key</code> or <code>value</code> are
     *             <code>null</code>.
     */
    public static void put(Object key, Object value) {
        if (key == null) {
            throw new IllegalArgumentException("key cannot be null");
        }
        if (value == null) {
            throw new IllegalArgumentException("value cannot be null.  If you"
                    + "are trying to unbind a resource" + "from the thread, use the "
                    + "'remove' method instead.");
        }

        getResources().put(key, value);

        if (logger.isTraceEnabled()) {
            String msg = "Bound value of type [" + value.getClass() + "] for key [" + key
                    + "] to thread " + "[" + Thread.currentThread().getName() + "]";
            logger.trace(msg);
        }
    }

    /**
     * Unbinds the value for the given <code>key</code> from the current
     * thread.
     *
     * @param key
     *            The key identifying the value bound to the current thread.
     * @return the object unbound or <tt>null</tt> if there was nothing bound
     *         under the specified <tt>key</tt> name.
     */
    public static Object remove(Object key) {
        Object value = getResources().remove(key);

        if ((value != null) && logger.isTraceEnabled()) {
            String msg = "Removed value of type [" + value.getClass() + "] for key [" + key + "]"
                    + "from thread [" + Thread.currentThread().getName() + "]";
            logger.trace(msg);
        }

        return value;
    }

    /**
     * Returns true if a value for the <code>key</code> is bound to the
     * current thread, false otherwise.
     *
     * @param key
     *            the key that may identify a value bound to the current thread.
     * @return true if a value for the key is bound to the current thread, false
     *         otherwise.
     */
    public static boolean containsKey(Object key) {
        return getResources().containsKey(key);
    }

    /**
     * Removes all values bound to this ThreadContext.
     *
     * <p>This operation is meant as a clean-up operation that may be called at the end of
     * thread execution to prevent data corruption in a pooled thread environment.
     */
    public static void clear() {
        getResources().clear();
        if ( logger.isTraceEnabled() ) {
            logger.trace( "Removed all ThreadContext values" );
        }

    }

}

