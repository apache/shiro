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
package org.apache.shiro.spring.web.config;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @since 1.4.0
 */
public class DefaultShiroFilterChainDefinition implements ShiroFilterChainDefinition {

    private final Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();

    public void addPathDefinition(String antPath, String definition) {
        filterChainDefinitionMap.put(antPath, definition);
    }

    public void addPathDefinitions(Map<String, String> pathDefinitions) {
        filterChainDefinitionMap.putAll(pathDefinitions);
    }

    @Override
    public Map<String, String> getFilterChainMap() {
        return filterChainDefinitionMap;
    }
}
