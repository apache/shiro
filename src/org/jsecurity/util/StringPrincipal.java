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

import java.security.Principal;

/**
 * Simple utility class for representing a <tt>String</tt> as a <tt>Principal</tt>.  This is
 * particularly useful for representing a database String (char/varchar) primary key or
 * username as a Principal.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class StringPrincipal implements Principal, java.io.Serializable {

    private String value = null;

    public StringPrincipal(){}

    public StringPrincipal( String value ) {
        setValue( value );
    }

    public String getValue() {
        return value;
    }

    public void setValue( String value ) {
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
        if ( obj instanceof StringPrincipal ) {
            return getValue().equals( ((StringPrincipal)obj).getValue() );
        } else {
            return false;
        }
    }

    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {
        try {
            StringPrincipal sp = (StringPrincipal)super.clone();
            sp.setValue( getValue() ); //Strings are immutable, no need to clone
            return sp;
        } catch ( CloneNotSupportedException e ) {
            throw new InternalError( "Unable to clone StringPrincipal");
        }
    }

    public String toString() {
        return getValue();
    }

    public String getName() {
        return toString();
    }

}
