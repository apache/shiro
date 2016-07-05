/*
 * Copyright 2013 Harald Wellmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ops4j.pax.shiro.cdi.web;

import java.util.Map;

import javax.enterprise.inject.spi.BeanManager;

import org.apache.shiro.config.Ini;
import org.apache.shiro.config.Ini.Section;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.ops4j.pax.shiro.cdi.impl.NamedBeanMap;


/**
 * A CDI-aware extension of {@link WebIniSecurityManagerFactory}. Constructs a named bean
 * map from the CDI BeanManager and uses these beans as additional default for Shiro
 * bean lookup.
 * 
 * @author Harald Wellmann
 *
 */
public class CdiWebIniSecurityManagerFactory extends WebIniSecurityManagerFactory {
    
    
    private Map<String, ?> namedBeanMap;

    public CdiWebIniSecurityManagerFactory(BeanManager beanManager) {
        this.namedBeanMap = new NamedBeanMap(beanManager);
    }
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    protected Map<String, ?> createDefaults(Ini ini, Section mainSection) {
        Map defaults = super.createDefaults(ini, mainSection);
        defaults.putAll(namedBeanMap);
        return defaults;
    }    
}
