/*
 * Copyright (C) 2007 Jeremy Haile
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
package org.jsecurity.samples.spring;

import org.jsecurity.authz.annotation.RolesRequired;

/**
 * Business manager interface used for sample application.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface SampleManager {

    /**
     * Returns the value stored in the user's session.
     * @return the value.
     */
    String getValue();


    /**
     * Sets a value to be stored in the user's session.
     * @param newValue the new value to store in the user's session.
     */
    void setValue(String newValue);

    /**
     * Method that requires <tt>role1</tt> in order to be invoked.
     */
    @RolesRequired( "role1" )
    void secureMethod1();

    /**
     * Method that requires <tt>role2</tt> in order to be invoked.
     */
    @RolesRequired( "role2" )
    void secureMethod2();
}
