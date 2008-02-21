/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
import org.jsecurity.context.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

/**
 * A ThreadContext provides a means of binding and unbinding objects to the
 * current thread based on key/value pairs.
 *
 * <p>An internal {@link java.util.HashMap} is used to maintain the key/value pairs
 * for each thread. If a Thread is pooled or reused, the internal map will not
 * be cleared upon thread reuse. It is the application's responsibility to bind
 * and remove values as necessary.</p>
 *
 * <p>If the desired behavior is to ensure that Thread data is not shared across
 * threads in a pooled or reusable Threaded environment, the application must
 * bind and remove any necessary values at the beginning and end of stack
 * execution, respectively (i.e. individually explicitly or all via the <tt>clear</tt> method).</p>
 *
 * @see #clear()
 * 
 * @since 0.1
 * @author Les Hazlewood
 */
@SuppressWarnings( value = { "unchecked", "unsafe" } )
public abstract class ThreadContext {

    protected static transient final Log logger = LogFactory.getLog( ThreadContext.class );

    public static final String SUBJECT_KEY = Subject.class.getName() + "_THREAD_CONTEXT_KEY";
    public static final String INET_ADDRESS_KEY = InetAddress.class.getName() + "_JSECURITY_THREAD_CONTEXT_KEY";
    public static final String SERVLET_REQUEST_KEY = ServletRequest.class.getName() + "_JSECURITY_THREAD_CONTEXST_KEY";
    public static final String SERVLET_RESPONSE_KEY = ServletResponse.class.getName() + "_JSECURITY_THREAD_CONTEXT_KEY";

    protected static ThreadLocal<Map<Object, Object>> resources =
        new InheritableThreadLocal<Map<Object, Object>>() {
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
     * @param key the key that identifies the value to return
     * @return the object keyed by <code>key</code> or <code>null</code> if
     *         no value exists for the specified <code>key</code>
     */
    public static Object get( Object key ) {
        if ( logger.isTraceEnabled() ) {
            String msg = "get() - in thread [" + Thread.currentThread().getName() + "]";
            logger.trace( msg );
        }
        Object value = getResources().get( key );
        if ( ( value != null ) && logger.isTraceEnabled() ) {
            String msg = "Retrieved value of type [" + value.getClass().getName() + "] for key [" +
                key + "] " + "bound to thread [" + Thread.currentThread().getName() + "]";
            logger.trace( msg );
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
    public static void put( Object key, Object value ) {
        if ( key == null ) {
            throw new IllegalArgumentException( "key cannot be null" );
        }

        if ( value == null ) {
            remove( key );
            return;
        }

        getResources().put( key, value );

        if ( logger.isTraceEnabled() ) {
            String msg = "Bound value of type [" + value.getClass().getName() + "] for key [" +
                key + "] to thread " + "[" + Thread.currentThread().getName() + "]";
            logger.trace( msg );
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
    public static Object remove( Object key ) {
        Object value = getResources().remove( key );

        if ( ( value != null ) && logger.isTraceEnabled() ) {
            String msg = "Removed value of type [" + value.getClass().getName() + "] for key [" +
                key + "]" + "from thread [" + Thread.currentThread().getName() + "]";
            logger.trace( msg );
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
    public static boolean containsKey( Object key ) {
        return getResources().containsKey( key );
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
        if ( logger.isTraceEnabled() ) {
            logger.trace( "Removed all ThreadContext values from thread [" + Thread.currentThread().getName() + "]" );
        }
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound Subject.  If there is no
     * Subject bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <pre>
     * return (Subject)get( SECURITY_CONTEXT_KEY );</pre>
     *
     * <p>This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindSubject() unbindSubject()} instead.
     *
     * @return the Subject object bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static Subject getSubject() {
        return (Subject)get(SUBJECT_KEY);
    }


    /**
     * Convenience method that simplifies binding a Subject to the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the security context is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (subject != null) {
     *     put( SECURITY_CONTEXT_KEY, subject );
     * }</pre>
     *
     * @param subject the Subject object to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind( Subject subject) {
        if ( subject != null ) {
            put(SUBJECT_KEY, subject);
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local Subject from the thread.
     * 
     * <p>The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     *
     * <pre>
     * return (Subject)remove( SECURITY_CONTEXT_KEY );</pre>
     *
     * <p>If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getSubject() getSubject()} method for that purpose.
     *
     * @return the Subject object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static Subject unbindSubject() {
        return (Subject)remove(SUBJECT_KEY);
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound InetAddress.  If there is no
     * InetAddress bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <pre>
     * return (InetAddress)get( INET_ADDRESS_KEY );</pre>
     *
     * <p>This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindInetAddress() unbindInetAddress} instead.
     *
     * @return the InetAddress object bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static InetAddress getInetAddress() {
        return (InetAddress)get( INET_ADDRESS_KEY );
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
    public static void bind( InetAddress inetAddress ) {
        if ( inetAddress != null ) {
            put( INET_ADDRESS_KEY, inetAddress );
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local InetAddress from the thread.
     *
     * <p>The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     *
     * <pre>
     * return (InetAddress)remove( INET_ADDRESS_KEY );</pre>
     *
     * <p>If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getInetAddress() getInetAddress()} method for that purpose.
     *
     * @return the InetAddress object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static InetAddress unbindInetAddress() {
        return (InetAddress)remove( INET_ADDRESS_KEY );
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound ServletRequest.  If there is no
     * ServletRequest bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <pre>
     * return (ServletRequest)get( SERVLET_REQUEST_KEY );</pre>
     *
     * <p>This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindServletRequest() unbindServletRequest} instead.
     *
     * @return the ServletRequest bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static ServletRequest getServletRequest() {
        return (ServletRequest)get( SERVLET_REQUEST_KEY );
    }

    /**
     * Convenience method that simplifies binding a ServletRequest to the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the servletRequest is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (servletRequest != null) {
     *     put( SERVLET_REQUEST_KEY, session );
     * }</pre>
     *
     * @param servletRequest the ServletRequest object to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind( ServletRequest servletRequest ) {
        if ( servletRequest != null ) {
            put( SERVLET_REQUEST_KEY, servletRequest );
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local ServletRequest from the thread.
     *
     * <p>The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     *
     * <pre>
     * return (ServletRequest)remove( SERVLET_REQUEST_KEY );</pre>
     *
     * <p>If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getServletRequest() getServletRequest()} method for that purpose.
     *
     * @return the Session object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static ServletRequest unbindServletRequest() {
        return (ServletRequest)remove( SERVLET_REQUEST_KEY );
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound ServletResponse.  If there is no
     * ServletResponse bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <pre>
     * return (ServletResponse)get( SERVLET_RESPONSE_KEY );</pre>
     *
     * <p>This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindServletResponse() unbindServletResponse} instead.
     *
     * @return the ServletResponse bound to the thread, or <tt>null</tt> if there isn't one bound.
     * @since 0.2
     */
    public static ServletResponse getServletResponse() {
        return (ServletResponse)get( SERVLET_RESPONSE_KEY );
    }

    /**
     * Convenience method that simplifies binding a ServletResponse to the ThreadContext.
     *
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the servletResponse is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     *
     * <pre>
     * if (servletResponse != null) {
     *     put( SERVLET_RESPONSE_KEY, session );
     * }</pre>
     *
     * @param servletResponse the ServletResponse object to bind to the thread.  If the argument is null, nothing will be done.
     * @since 0.2
     */
    public static void bind( ServletResponse servletResponse ) {
        if ( servletResponse != null ) {
            put( SERVLET_RESPONSE_KEY, servletResponse );
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local ServletResponse from the thread.
     *
     * <p>The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     *
     * <pre>
     * return (ServletResponse)remove( SERVLET_RESPONSE_KEY );</pre>
     *
     * <p>If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getServletResponse() getServletResponse()} method for that purpose.
     *
     * @return the Session object previously bound to the thread, or <tt>null</tt> if there was none bound.
     * @since 0.2
     */
    public static ServletResponse unbindServletResponse() {
        return (ServletResponse)remove( SERVLET_RESPONSE_KEY );
    }



}

