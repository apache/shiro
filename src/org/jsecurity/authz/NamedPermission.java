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
package org.jsecurity.authz;

/**
 * A Permission subinterface that introduces a {@link #getName name} property to support a single value that can 
 * represent behavior or access to a resource.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface NamedPermission extends Permission {

    public static final String WILDCARD = "*";
    public static final char WILDCARD_CHAR = '*';

    /**
     * Returns the 'name' of this permission, typically whatever value that best represents behavior or access to a
     * resource.  If the value returned is the {@link #WILDCARD WILDCARD} constant, it means <b>all</b> possible name
     * values for the <tt>Permission</tt> type.
     *
     * <p>Somewhat abstract, the 'name' of a permission can mean whatever
     * the application wishes it to mean.  In many systems it would be something like 'createUsers' or
     * 'userSearch', or anything else the application feels is meaningful.
     *
     * <p>The {@link #WILDCARD WILDCARD} constant means it would <em>{@link #implies(Permission) imply}</em> all other
     * Permission <tt>name</tt>s of the same Permission type.  In other words, the following must always be true:
     *
     * <p><code>Permission wildcardPerm = new com.domain.SomeNamedPermission( WILDCARD );<br/>
     * Permission specificPerm = new com.domain.SomeNamedPermission( "anyValue" );<br/>
     * wildcardPerm.implies( specificPerm ) === true</code>
     *
     * @return the 'name' of the permission, where the name value usually represents some named behavior or resource
     * access.
     */
    String getName();
}
