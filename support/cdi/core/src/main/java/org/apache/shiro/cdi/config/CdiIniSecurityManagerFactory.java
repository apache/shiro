/**
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
package org.apache.shiro.cdi.config;

import java.util.Map;

import javax.enterprise.inject.spi.BeanManager;

import org.apache.shiro.cdi.impl.NamedBeanMap;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.config.Ini.Section;


/**
 * A CDI-aware extension of {@code IniSecurityManagerFactory}, allowing to reference CDI
 * managed beans qualified with {@code @ShiroIni} in Shiro INI files.
 */
public class CdiIniSecurityManagerFactory extends IniSecurityManagerFactory {
    
    
    private NamedBeanMap namedBeanMap;

    /**
     * Constructs a security manager factory for the given INI resource path, considering
     * CDI beans from the given bean manager.
     * 
     * @param iniResourcePath INI file resource path
     * @param beanManager the current CDI bean manager
     */
    public CdiIniSecurityManagerFactory(String iniResourcePath, BeanManager beanManager) {
        super(iniResourcePath);
        namedBeanMap = new NamedBeanMap(beanManager);
    }
    
    /**
     * Constructs a security manager factory for the given INI object, considering
     * CDI beans from the given bean manager.
     * 
     * @param ini INI object
     * @param beanManager the current CDI bean manager
     */
    public CdiIniSecurityManagerFactory(Ini ini, BeanManager beanManager) {
        super(ini);
        namedBeanMap = new NamedBeanMap(beanManager);
    }
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    protected Map<String, ?> createDefaults(Ini ini, Section mainSection) {
        Map defaults = super.createDefaults(ini, mainSection);
        defaults.putAll(namedBeanMap);
        return defaults;
    }        
}
