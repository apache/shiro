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
package org.apache.shiro.cdi.extension;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.cdi.bean.SecurityManagerBean;
import org.apache.shiro.cdi.interceptor.ShiroInterceptorBridge;
import org.apache.shiro.cdi.wrap.NonBindingAnnotation;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessBean;
import java.lang.annotation.Annotation;

import static java.util.Arrays.asList;
import static org.apache.shiro.cdi.loader.Load.load;

public class ShiroExtension implements Extension {
    private boolean securityManager;
    private SecurityManagerBean bean;
    private SecurityManager manager;

    void makeShiroAnnotationsInterceptorBindings(@Observes final BeforeBeanDiscovery beforeBeanDiscovery, final BeanManager bm) {
        for (final Class<? extends Annotation> type : asList(
                RequiresRoles.class, RequiresPermissions.class,
                RequiresAuthentication.class, RequiresUser.class, RequiresGuest.class)) {
            beforeBeanDiscovery.addInterceptorBinding(new NonBindingAnnotation(bm.createAnnotatedType(type)));
        }
        for (final Class<?> type : asList(
                ShiroInterceptorBridge.RequiresRolesInterceptor.class,
                ShiroInterceptorBridge.RequirePermissionsInterceptor.class,
                ShiroInterceptorBridge.RequiresAuthenticationInterceptor.class,
                ShiroInterceptorBridge.RequiresUserInterceptor.class,
                ShiroInterceptorBridge.RequiresGuestInterceptor.class)) {
            beforeBeanDiscovery.addAnnotatedType(bm.createAnnotatedType(type));
        }
    }

    void hasSecurityManager(@Observes final ProcessBean<SecurityManager> securityManagerProcessBean) {
        securityManager = securityManager || !SecurityManagerBean.class.isInstance(securityManagerProcessBean.getBean());
    }

    void addSecurityManagerIfNeeded(@Observes final AfterBeanDiscovery afterBeanDiscovery) {
        if (securityManager) {
            return;
        }
        newSecurityManager();
        bean = new SecurityManagerBean(manager.getClass());
        afterBeanDiscovery.addBean(bean);
    }

    void initSecurityManagerBean(@Observes final AfterDeploymentValidation afterDeploymentValidation) {
        if (bean != null) {
            bean.initSecurityManagerBean(manager);
        }
    }

    public boolean isSecurityManager() {
        return securityManager;
    }

    private void newSecurityManager() {
        try {
            manager = SecurityManager.class.cast(load("org.apache.shiro.web.mgt.DefaultWebSecurityManager", DefaultSecurityManager.class).newInstance());
        } catch (final IllegalAccessException e) {
            throw new IllegalStateException(e);
        } catch (final InstantiationException e) {
            throw new IllegalStateException(e);
        }
    }

    public SecurityManager getSecurityManager() {
        return manager;
    }
}
