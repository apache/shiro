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
package org.jsecurity.util;

import java.security.Principal;
import java.util.UUID;

/**
 * Simple utility class for representing a <tt>UUID</tt> as a <tt>Principal</tt>.  This is
 * useful for representing a database UUID primary key as a Principal.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class UUIDPrincipal implements Principal, java.io.Serializable {

    private UUID value = null;

    public UUIDPrincipal(){}

    public UUIDPrincipal( UUID value ) {
        setValue( value );
    }

    public UUID getValue() {
        return value;
    }

    public void setValue( UUID value ) {
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
        if ( obj instanceof UUIDPrincipal ) {
            return getValue().equals( ((UUIDPrincipal)obj).getValue() );
        } else {
            return false;
        }
    }

    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {
        try {
            UUIDPrincipal uuidp = (UUIDPrincipal)super.clone();
            uuidp.setValue( getValue() ); //UUID's are immutable, no need to clone
            return uuidp;
        } catch ( CloneNotSupportedException e ) {
            throw new InternalError( "Unable to clone UUIDPrincipal");
        }
    }

    public String toString() {
        return getValue().toString();
    }

    public String getName() {
        return toString();
    }

}
