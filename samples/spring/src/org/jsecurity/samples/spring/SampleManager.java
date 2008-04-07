/*
 * Copyright 2005-2008 Jeremy Haile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.samples.spring;

import org.jsecurity.authz.annotation.RequiresRoles;
import org.jsecurity.authz.annotation.RequiresPermissions;

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
    @RequiresRoles( "role1" )
    void secureMethod1();

    /**
     * Method that requires <tt>role2</tt> in order to be invoked.
     */
    @RequiresRoles( "role2" )
    void secureMethod2();

    /**
     * Method that requires <tt>permission1</tt> in order to be invoked.
     */
    @RequiresPermissions( "permission2" )
    void secureMethod3();
}
