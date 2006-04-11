/*
 * Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.ri.util;

import java.security.Principal;

/**
 * Simple utility class for representing an <tt>Integer</tt> as a <tt>Principal</tt>.  This is
 * useful for representing a database integer primary key as a Principal.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class IntegerPrincipal implements Principal, java.io.Serializable {

    private Integer value = null;

    public IntegerPrincipal(){}

    public IntegerPrincipal( Integer value ) {
        setValue( value );
    }

    public Integer getValue() {
        return value;
    }

    public void setValue( Integer value ) {
        if ( value == null ) {
            String msg = "Cannot accept null value argument";
            throw new NullPointerException( msg );
        }
        this.value = value;
    }

    public int hashCode() {
        return getValue().hashCode();
    }

    public boolean equals( Object obj ) {
        if ( obj instanceof IntegerPrincipal ) {
            return getValue().equals( ((IntegerPrincipal)obj).getValue() );
        } else {
            return false;
        }
    }

    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {
        try {
            IntegerPrincipal ip = (IntegerPrincipal)super.clone();
            ip.setValue( getValue() ); //Integers are immutable, no need to clone
            return ip;
        } catch ( CloneNotSupportedException e ) {
            throw new InternalError( "Unable to clone IntegerPrincipal");
        }
    }

    public String toString() {
        return getValue().toString();
    }

    public String getName() {
        return toString();
    }

}
