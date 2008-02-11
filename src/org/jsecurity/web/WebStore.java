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
package org.jsecurity.web;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

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

    T retrieveValue( ServletRequest request, ServletResponse response );

    void storeValue( T value, ServletRequest request, ServletResponse response );

    void removeValue( ServletRequest request, ServletResponse response );
}
