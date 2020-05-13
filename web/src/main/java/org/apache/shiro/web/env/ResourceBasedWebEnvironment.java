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
package org.apache.shiro.web.env;

import org.apache.shiro.config.ResourceConfigurable;
import org.apache.shiro.lang.util.StringUtils;

/**
 * Abstract implementation for {@code WebEnvironment}s that can be initialized via resource paths (config files).
 *
 * @since 1.2
 */
public abstract class ResourceBasedWebEnvironment extends DefaultWebEnvironment implements ResourceConfigurable {

    private String[] configLocations;

    public String[] getConfigLocations() {
        return configLocations;
    }

    public void setConfigLocations(String locations) {
        if (!StringUtils.hasText(locations)) {
            throw new IllegalArgumentException("Null/empty locations argument not allowed.");
        }
        String[] arr = StringUtils.split(locations);
        setConfigLocations(arr);
    }

    public void setConfigLocations(String[] configLocations) {
        this.configLocations = configLocations;
    }

}
