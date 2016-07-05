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
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.ops4j.pax.shiro.cdi.impl.BeanManagerProvider;


/**
 * An extension of {@link IniWebEnvironment} which makes CDI beans qualified with 
 * {@code @ShiroIni} available to Shiro, to be referenced in INI files.
 *
 * @author Harald Wellmann
 */
public class CdiIniWebEnvironment extends IniWebEnvironment {
    
    
    @Override
    protected WebSecurityManager createWebSecurityManager() {
        Ini ini = getIni();
        
        if (CollectionUtils.isEmpty(ini)) {
            ini = null;
        }
        
        BeanManager beanManager = BeanManagerProvider.getBeanManager();
        IniSecurityManagerFactory factory = new CdiWebIniSecurityManagerFactory(beanManager);
        factory.setIni(ini);

        WebSecurityManager wsm = (WebSecurityManager)factory.getInstance();
        Map<String, ?> beans = factory.getBeans();
        if (!CollectionUtils.isEmpty(beans)) {
            this.objects.putAll(beans);
        }

        return wsm;
    }    
}
