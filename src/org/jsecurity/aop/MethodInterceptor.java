/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity.aop;

/**
 * A <tt>MethodInterceptor</tt> intercepts a <tt>MethodInvocation</tt> to perform before or after logic (aka 'advice').
 *
 * <p>JSecurity's implementations of this interface mostly have to deal with ensuring a current Subject has the
 * ability to execute the method before allowing it to continue.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface MethodInterceptor {
    
    Object invoke( MethodInvocation methodInvocation ) throws Throwable;

}
