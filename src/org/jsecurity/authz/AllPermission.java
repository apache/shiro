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

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An all <tt>AllPermission</tt> instance is one that always implies any other permission; that is, its
 * {@link #implies implies} method always returns <tt>true</tt>.
 *
 * <p>You should be very careful about the users, roles, and/or groups to which you assign this permission since
 * those respective entities will have the ability to do anything.  As such, an instance of this class
 * is typically only assigned only to "root" or "administrator" users or roles.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class AllPermission extends AbstractPermission {

    private static final LinkedHashSet<String> possibleActions = initPossibleActionsSet();

    private static LinkedHashSet<String> initPossibleActionsSet() {
        LinkedHashSet<String> possibleActions = new LinkedHashSet<String>(1);
        possibleActions.add( WILDCARD );
        return possibleActions;
    }

    public AllPermission() {
        super( WILDCARD, possibleActions );
    }

    public Set<String> getPossibleActions() {
        return possibleActions;
    }

    public boolean implies( Permission p ) {
        return true;    
    }
}
