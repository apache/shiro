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

import org.jsecurity.authz.NamedPermission;
import org.jsecurity.authz.Permission;

/**
 * Extends SimplePermission for Permission behavior, and supports the <tt>NamedPermission</tt> interface via
 * a <tt>name</tt> attribute.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SimpleNamedPermission extends SimplePermission implements NamedPermission {

    private String name = null;

    public SimpleNamedPermission() {
        super();
    }

    public SimpleNamedPermission( String name ) {
        this.name = name;
    }

    public String getTarget() {
        return name;
    }

    public String getName() {
        return this.name;
    }

    protected void setName( String name ) {
        this.name = name;
    }

    public boolean implies( Permission p ) {
        boolean implies = false;

        if ( super.implies( p ) ) {

            if ( p instanceof NamedPermission ) {
                NamedPermission np = (NamedPermission)p;

                String name = getName();

                if ( name != null ) {
                    implies = name.equals( WILDCARD ) || name.contains( np.getName() );
                } else {
                    implies = ( np.getName() == null );
                }
            }
        }

        return implies;
    }

    protected StringBuffer toStringBuffer() {
        StringBuffer sb = new StringBuffer();
        sb.append( "(\"" ).append( getClass().getName() ).append( "\" " );
        sb.append( "\"" ).append( getName() ).append( "\")" );
        return sb;
    }

    public boolean equals( Object o ) {

        if ( o instanceof NamedPermission ) {
            NamedPermission np = (NamedPermission)o;

            return super.equals( np ) &&
                   (getName() != null ? getName().equals( np.getName() ) : np.getName() == null );

        }

        return false;
    }

    public int hashCode() {
        int result = super.hashCode();
        result = 29 * result + ( getName() != null ? getName().hashCode() : 0 );
        return result;
    }

    public Object clone() {
        SimpleNamedPermission np = (SimpleNamedPermission)super.clone();
        np.name = getName();
        return np;
    }
}
