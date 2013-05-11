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
package org.apache.shiro.web.config;

import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.filter.mgt.DefaultFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;

import javax.servlet.Filter;
import java.util.Map;

/**
 * Differs from the parent class only in the {@link #createDefaultInstance()} method, to
 * ensure a web-capable {@code SecurityManager} instance is created by default.
 *
 * @since 1.0
 */
public class WebIniSecurityManagerFactory extends IniSecurityManagerFactory {

    /**
     * Creates a new {@code WebIniSecurityManagerFactory} instance which will construct web-capable
     * {@code SecurityManager} instances.
     */
    public WebIniSecurityManagerFactory() {
        super();
    }

    /**
     * Creates a new {@code WebIniSecurityManagerFactory} instance which will construct web-capable
     * {@code SecurityManager} instances.  Uses the given {@link Ini} instance to construct the instance.
     *
     * @param config the Ini configuration that will be used to construct new web-capable {@code SecurityManager}
     *               instances.
     */
    public WebIniSecurityManagerFactory(Ini config) {
        super(config);
    }

    /**
     * Simply returns <code>new {@link DefaultWebSecurityManager}();</code> to ensure a web-capable
     * {@code SecurityManager} is available by default.
     *
     * @return a new web-capable {@code SecurityManager} instance.
     */
    @Override
    protected SecurityManager createDefaultInstance() {
        return new DefaultWebSecurityManager();
    }

    @SuppressWarnings({"unchecked"})
    @Override
    protected Map<String, ?> createDefaults(Ini ini, Ini.Section mainSection) {
        Map defaults = super.createDefaults(ini, mainSection);
        //add the default filters:
        Map<String, Filter> defaultFilters = DefaultFilter.createInstanceMap(null);
        defaults.putAll(defaultFilters);
        return defaults;
    }
}
