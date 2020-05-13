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

import org.apache.shiro.lang.util.Factory;

import javax.naming.NamingException;

/**
 * A factory implementation intended to be used to look up objects in jndi.
 * @param <T>
 * @since 1.2
 */
public class JndiObjectFactory<T> extends JndiLocator implements Factory<T> {

    private String resourceName;
    private Class<? extends T> requiredType;

    public T getInstance() {
        try {
            if(requiredType != null) {
                return requiredType.cast(this.lookup(resourceName, requiredType));
            } else {
                return (T) this.lookup(resourceName);
            }
        } catch (NamingException e) {
            final String typeName = requiredType != null ? requiredType.getName() : "object";
            throw new IllegalStateException("Unable to look up " + typeName + " with jndi name '" + resourceName + "'.", e);
        }
    }

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public Class<? extends T> getRequiredType() {
        return requiredType;
    }

    public void setRequiredType(Class<? extends T> requiredType) {
        this.requiredType = requiredType;
    }
}
