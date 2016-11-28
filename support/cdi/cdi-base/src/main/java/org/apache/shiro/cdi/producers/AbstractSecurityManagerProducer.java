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
package org.apache.shiro.cdi.producers;

import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractSecurityManagerProducer {

    @Inject
    private Instance<Initializable> initializables;

    @Inject
    private Instance<Destroyable> destroyables;

    @Inject
    private Instance<Object> objectInstances;




    protected abstract DefaultSecurityManager securityManager(DefaultSecurityManager securityManager,
                                                              Instance<Realm> realms,
                                                              EventBus eventBus,
                                                              SessionManager sessionManager,
                                                              Instance<CacheManager> cacheManager,
                                                              SubjectDAO subjectDAO,
                                                              SubjectFactory subjectFactory,
                                                              Instance<RememberMeManager> rememberMeManager,
                                                              AuthenticationStrategy authenticationStrategy,
                                                              Instance<PermissionResolver> permissionResolver,
                                                              Instance<RolePermissionResolver> rolePermissionResolver);


    protected <T extends DefaultSecurityManager> T configureSecurityManager(T securityManager,
                                                                            Instance<Realm> realms,
                                                                            EventBus eventBus,
                                                                            SessionManager sessionManager,
                                                                            Instance<CacheManager> cacheManager,
                                                                            SubjectDAO subjectDAO,
                                                                            SubjectFactory subjectFactory,
                                                                            Instance<RememberMeManager> rememberMeManager,
                                                                            AuthenticationStrategy authenticationStrategy,
                                                                            Instance<PermissionResolver> permissionResolver,
                                                                            Instance<RolePermissionResolver> rolePermissionResolver) {
        securityManager.setEventBus(eventBus);

        // Set the cache manager if available
        if(!cacheManager.isUnsatisfied()) {
            securityManager.setCacheManager(cacheManager.get());
        }

        if(!rememberMeManager.isUnsatisfied()) {
            securityManager.setRememberMeManager(rememberMeManager.get());
        }

        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setAuthenticationStrategy(authenticationStrategy);
        ModularRealmAuthorizer authorizer = new ModularRealmAuthorizer();

        if (permissionResolver != null && !permissionResolver.isUnsatisfied()) {
            authorizer.setPermissionResolver(permissionResolver.get());
        }

        if (rolePermissionResolver != null && !rolePermissionResolver.isUnsatisfied()) {
            authorizer.setRolePermissionResolver(rolePermissionResolver.get());
        }

        securityManager.setAuthenticator(authenticator);
        securityManager.setAuthorizer(authorizer);
        securityManager.setSessionManager(sessionManager);
        securityManager.setSubjectDAO(subjectDAO);
        securityManager.setSubjectFactory(subjectFactory);

        List<Realm> realmList = new ArrayList<>();
        for (Realm realm : realms) {
            realmList.add(realm);
        }
        securityManager.setRealms(realmList);

        return securityManager;
    }


//    @PostConstruct
//    void init() {
//        for(Initializable initializable : initializables) {
//            initializable.init();
//        }
//    }

//    @PreDestroy
//    void destroy() throws Exception {
//        for(Destroyable destroyable : destroyables) {
//            destroyable.destroy();
//        }
//    }
}
