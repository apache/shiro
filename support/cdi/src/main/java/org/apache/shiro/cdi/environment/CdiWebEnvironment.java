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
package org.apache.shiro.cdi.environment;

import org.apache.shiro.env.RequiredTypeException;
import org.apache.shiro.web.env.DefaultWebEnvironment;

public class CdiWebEnvironment extends DefaultWebEnvironment {
    private final CdiLookups lookups;

    public CdiWebEnvironment(final CdiLookups lookups) {
        this.lookups = lookups;
    }

    @Override
    public <T> T getObject(final String name, final Class<T> requiredType) throws RequiredTypeException {
        final T value = super.getObject(name, requiredType);
        if (value != null) {
            return value;
        }
        return lookups.getObject(name, requiredType);
    }

    @Override
    public void destroy() throws Exception {
        super.destroy();
        lookups.close();
    }
}
