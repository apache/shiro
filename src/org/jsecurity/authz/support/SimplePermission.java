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
package org.jsecurity.authz.support;

import org.jsecurity.authz.Permission;

import java.io.Serializable;

/**
 * Simple implementation of the Permission interface, primarily used as a convenient base for subclassing more
 * meaningful Permission classes.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SimplePermission implements Permission, Serializable {

    public SimplePermission() {
    }

    /**
     * Very simple implementation that only returns true if the argument is not null and the argument's class name
     * is equal to this instances's class name.  That is, it merely returns:
     * <code>getClass().getName().equals( argument.getClass().getName() );</code>.
     *
     * <p>Most will subclass this and override this method to implement something more meaningful to the application.
     *
     * @param p the Permission instance to check
     * @return <tt>true</tt> if this instance's class and the argument's class names are equal, <tt>false</tt> otherwise.
     */
    public boolean implies( Permission p ) {
        return p != null && getClass().getName().equals( p.getClass().getName() );
    }

    public String toString() {
        return toStringBuffer().toString();
    }

    protected StringBuffer toStringBuffer() {
        return new StringBuffer( getClass().getName() );
    }

    public boolean equals( Object o ) {
        return o == this || o != null && getClass().getName().equals( o.getClass().getName() );

    }

    public int hashCode() {
        return getClass().getName().hashCode();
    }

    @Override
    @SuppressWarnings( { "CloneDoesntDeclareCloneNotSupportedException" } )
    public Object clone() {
        SimplePermission sp;
        try {
            sp = (SimplePermission)super.clone();
        } catch ( CloneNotSupportedException e ) {
            String msg = "Unable to clone SimplePermission of type [" +
                    getClass().getName() + "].  Check implementation (this should never " +
                    "happen).";
            throw new InternalError( msg );
        }
        return sp;
    }
}
