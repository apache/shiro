package org.jsecurity.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A <tt>WebStore</tt> is a storage mechanism for a single object accessible during a web request.
 *
 * <p>It is used to make objects associated with the transient request persistent beyond the request so that they can
 * be retrieved upon a later request.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public interface WebStore<T> {

    T retrieveValue( HttpServletRequest request, HttpServletResponse response );

    void storeValue( T value, HttpServletRequest request, HttpServletResponse response );   
}
