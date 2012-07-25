/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.jndi;

import javax.naming.Context;
import javax.naming.NamingException;

/**
 * Callback interface to be implemented by classes that need to perform an
 * operation (such as a lookup) in a JNDI context. This callback approach
 * is valuable in simplifying error handling, which is performed by the
 * JndiTemplate class. This is a similar to JdbcTemplate's approach.
 *
 * <p>Note that there is hardly any need to implement this callback
 * interface, as JndiTemplate provides all usual JNDI operations via
 * convenience methods.
 *
 * <p>Note that this interface is an exact copy of the Spring Framework's identically named interface from
 * their 2.5.4 distribution - we didn't want to re-invent the wheel, but not require a full dependency on the
 * Spring framework, nor does Spring make available only its JNDI classes in a small jar, or we would have used that.
 * Since Shiro is also Apache 2.0 licensed, all regular licenses and conditions and authors have remained in tact.
 *
 * @see JndiTemplate
 */
public interface JndiCallback {

    /**
     * Do something with the given JNDI context.
     * Implementations don't need to worry about error handling
     * or cleanup, as the JndiTemplate class will handle this.
     *
     * @param ctx the current JNDI context
     * @return a result object, or <code>null</code>
     * @throws NamingException if thrown by JNDI methods
     */
    Object doInContext(Context ctx) throws NamingException;

}
