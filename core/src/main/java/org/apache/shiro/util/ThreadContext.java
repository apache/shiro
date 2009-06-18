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

import java.io.Serializable;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;


/**
 * A ThreadContext provides a means of binding and unbinding objects to the
 * current thread based on key/value pairs.
 *
 * <p>An internal {@link java.util.HashMap} is used to maintain the key/value pairs
 * for each thread.</p>
 *
 * <p>If the desired behavior is to ensure that bound data is not shared across
 * threads in a pooled or reusable threaded environment, the application (or more likely a framework) must
 * bind and remove any necessary values at the beginning and end of stack
 * execution, respectively (i.e. individually explicitly or all via the <tt>clear</tt> method).</p>
 *
 * @author Les Hazlewood
 * @see #clear()
 * @since 0.1
 */
@SuppressWarnings(value = {"unchecked", "unsafe"})
public abstract class ThreadContext {

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(ThreadContext.class);

    public static final String SECURITY_MANAGER_KEY = ThreadContext.class.getName() + "_SECURITY_MANAGER_KEY";
    public static final String SUBJECT_KEY = ThreadContext.class.getName() + "_SUBJECT_KEY";
    public static final String SESSION_ID_KEY = ThreadContext.class.getName() + "_SESSION_ID_KEY";
    public static final String INET_ADDRESS_KEY = ThreadContext.class.getName() + "_INET_ADDRESS_KEY";

    protected static ThreadLocal<Map<Object, Object>> resources =
            new InheritableThreadLocal<Map<Object, Object>>() {
                protected Map<Object, Object> initialValue() {
                    return new HashMap<Object, Object>();
                }

                /**
                 * This implementation was added to address a
                 * <a href="http://jsecurity.markmail.org/search/?q=#query:+page:1+mid:xqi2yxurwmrpqrvj+state:results">
                 * user-reported issue</a>.
                 * @param parentValue the parent value, a HashMap as defined in the {@link #initialValue()} method.
                 * @return the HashMap to be used by any parent-spawned child threads (a clone of the parent HashMap).
                 */
                protected Map<Object, Object> childValue(Map<Object, Object> parentValue) {
                    if (parentValue != null) {
                        return (Map<Object, Object>) ((HashMap<Object, Object>) parentValue).clone();
                    } else {
                        return null;
                    }
                }
            };

    /**
     * Default no-argument constructor.
     */
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
     * @param key the key that identifies the value to return
     * @return the object keyed by <code>key</code> or <code>null</code> if
     *         no value exists for the specified <code>key</code>
     */
    public static Object get(Object key) {
        if (log.isTraceEnabled()) {
            String msg = "get() - in thread [" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }
        Object value = getResources().get(key);
        if ((value != null) && log.isTraceEnabled()) {
            String msg = "Retrieved value of type [" + value.getClass().getName() + "] for key [" +
                    key + "] " + "bound to thread [" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }
        return value;
    }

    /**
     * Binds <tt>value</tt> for the given <code>key</code> to the current thread.
     *
     * <p>A <tt>null</tt> <tt>value</tt> has the same effect as if <tt>remove</tt> was called for the given
     * <tt>key</tt>, i.e.:
     *
     * <pre>
     * if ( value == null ) {
     *     remove( key );
     * }</pre>
     *
     * @param key   The key with which to identify the <code>value</code>.
     * @param value The value to bind to the thread.
     * @throws IllegalArgumentException if the <code>key</code> argument is <tt>null</tt>.
     */
    public static void put(Object key, Object value) {
        if (key == null) {
            throw new IllegalArgumentException("key cannot be null");
        }

        if (value == null) {
            remove(key);
            return;
        }

        getResources().put(key, value);

        if (log.isTraceEnabled()) {
            String msg = "Bound value of type [" + value.getClass().getName() + "] for key [" +
                    key + "] to thread " + "[" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }
    }

    /**
     * Unbinds the value for the given <code>key</code> from the current
     * thread.
     *
     * @param key The key identifying the value bound to the current thread.
     * @return the object unbound or <tt>null</tt> if there was nothing bound
     *         under the specified <tt>key</tt> name.
     */
    public static Object remove(Object key) {
        Object value = getResources().remove(key);

        if ((value != null) && log.isTraceEnabled()) {
            String msg = "Removed value of type [" + value.getClass().getName() + "] for key [" +
                    key + "]" + "from thread [" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }

        return value;
    }

    /**
     * Returns true if a value for the <code>key</code> is bound to the current thread, false otherwise.
     *
     * @param key the key that may identify a value bound to the current thread.
     * @return true if a value for the key is bound to the current thread, false
     *         otherwise.
     */
    public static boolean containsKey(Object key) {
        return getResources().containsKey(key);
    }

    /**
     * Removes <em>all</em> values bound to this ThreadContext, which includes any Subject, Session, or InetAddress
     * that may be bound by these respective objects' conveninece methods, as well as all values bound by your
     * application code.
     *
     * <p>This operation is meant as a clean-up operation that may be called at the end of
     * thread execution to prevent data corruption in a pooled thread environment.
     */
    public static void clear() {
        getResources().clear();
        if (log.isTraceEnabled()) {
            log.trace("Removed all ThreadContext values from thread [" + Thread.currentThread().getName() + "]");
        }
    }

    /**
     * Convenience method that simplifies retrieval of the application's SecurityManager instance from the current
     * thread. If there is no SecurityManager bound to the thread (probably because framework code did not bind it
     * to the thread), this method returns <tt>null</tt>.
     * <p/>
     * It is merely a convenient wrapper for the following:
     * <p/>
     * <code>return (SecurityManager)get( SECURITY_MANAGER_KEY );</code>
     * <p/>
     * This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindSecurityManager() unbindSecurityManager()} instead.
     *
     * @return the Subject object bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.9
     */
    public static org.apache.shiro.mgt.SecurityManager getSecurityManager() {
        return (SecurityManager) get(SECURITY_MANAGER_KEY);
    }


    /**
     * Convenience method that simplifies binding the application's SecurityManager instance to the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the SecurityManager is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (securityManager != null) {
     *     put( SECURITY_MANAGER_KEY, securityManager);
     * }</pre>
     *
     * @param securityManager the application's SecurityManager instance to bind to the thread.  If the argument is
     *                        null, nothing will be done.
     * @since 0.9
     */
    public static void bind(SecurityManager securityManager) {
        if (securityManager != null) {
            put(SECURITY_MANAGER_KEY, securityManager);
        }
    }

    /**
     * Convenience method that simplifies removal of the application's SecurityManager instance from the thread.
     * <p/>
     * The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     * <p/>
     * <code>return (SecurityManager)remove( SECURITY_MANAGER_KEY );</code>
     * <p/>
     * If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later
     * during thread execution), use the {@link #getSecurityManager() getSecurityManager()} method instead.
     *
     * @return the application's SecurityManager instance previously bound to the thread, or <tt>null</tt> if there
     *         was none bound.
     * @since 0.9
     */
    public static SecurityManager unbindSecurityManager() {
        return (SecurityManager) remove(SECURITY_MANAGER_KEY);
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound Subject.  If there is no
     * Subject bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <p/>
     * <code>return (Subject)get( SUBJECT_KEY );</code>
     * <p/>
     * This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindSubject() unbindSubject()} instead.
     *
     * @return the Subject object bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static Subject getSubject() {
        return (Subject) get(SUBJECT_KEY);
    }


    /**
     * Convenience method that simplifies binding a Subject to the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the Subject is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (subject != null) {
     *     put( SUBJECT_KEY, subject );
     * }</pre>
     *
     * @param subject the Subject object to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind(Subject subject) {
        if (subject != null) {
            put(SUBJECT_KEY, subject);
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local Subject from the thread.
     * <p/>
     * The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     * <p/>
     * <code>return (Subject)remove( SUBJECT_KEY );</code>
     * <p/>
     * If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getSubject() getSubject()} method for that purpose.
     *
     * @return the Subject object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static Subject unbindSubject() {
        return (Subject) remove(SUBJECT_KEY);
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound InetAddress.  If there is no
     * InetAddress bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <p/>
     * <code>return (InetAddress)get( INET_ADDRESS_KEY );</code>
     * <p/>
     * This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindInetAddress() unbindInetAddress} instead.
     *
     * @return the InetAddress object bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static InetAddress getInetAddress() {
        return (InetAddress) get(INET_ADDRESS_KEY);
    }

    /**
     * Convenience method that simplifies binding an InetAddress to the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the inetAddress is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (inetAddress != null) {
     *     put( INET_ADDRESS_KEY, inetAddress );
     * }</pre>
     *
     * @param inetAddress the InetAddress to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind(InetAddress inetAddress) {
        if (inetAddress != null) {
            put(INET_ADDRESS_KEY, inetAddress);
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local InetAddress from the thread.
     * <p/>
     * The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     * <p/>
     * <code>return (InetAddress)remove( INET_ADDRESS_KEY );</code>
     * <p/>
     * If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getInetAddress() getInetAddress()} method for that purpose.
     *
     * @return the InetAddress object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static InetAddress unbindInetAddress() {
        return (InetAddress) remove(INET_ADDRESS_KEY);
    }

    //TODO - complete JavaDoc

    public static Serializable getSessionId() {
        return (Serializable) get(SESSION_ID_KEY);
    }

    public static void bindSessionId(Serializable sessionId) {
        if (sessionId != null) {
            put(SESSION_ID_KEY, sessionId);
        }
    }

    public Serializable unbindSessionId() {
        return (Serializable) remove(SESSION_ID_KEY);

    }
}

