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
package org.apache.shiro.cdi.configurer;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cdi.loader.Load;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;

@ApplicationScoped
public class SecurityManagerConfigurer {
    @Inject
    private Instance<SecurityManager> manager;

    @Inject
    private Instance<Realm> realm;

    @Inject
    private Instance<Authenticator> authenticator;

    @Inject
    private Instance<Authorizer> authorizer;

    @Inject
    private Instance<CacheManager> cacheManager;

    @Inject
    private Instance<EventBus> eventBus;

    @Inject
    private Instance<SubjectDAO> subjectDAO;

    @Inject
    private Instance<SubjectFactory> subjectFactory;

    @Inject
    private Instance<SessionManager> sessionManager;

    @Inject
    private Instance<RememberMeManager> rememberMeManager;

    @Inject
    private Event<SecurityManager> securityManagerEvent;

    // here we use that philosophy: if set it was configured in the security manager producer otherwise use the produced value if there
    public SecurityManager configureManager(final SecurityManager manager) {
        if (!DefaultSecurityManager.class.isInstance(manager)) {
            securityManagerEvent.fire(manager); // to customize it through an observer
            return manager;
        }
        final DefaultSecurityManager mgr = DefaultSecurityManager.class.cast(manager);
        if ((mgr.getRealms() == null || mgr.getRealms().isEmpty()) && !realm.isUnsatisfied()) {
            // java 8: stream(realm.spliterator(), false).collect(toList())
            final Collection<Realm> list = new ArrayList<Realm>();
            for (final Realm r : realm) {
                list.add(r);
            }
            mgr.setRealms(list);
        }
        if (mgr.getAuthenticator() == null && !authenticator.isUnsatisfied()) {
            mgr.setAuthenticator(authenticator.get());
        }
        if (mgr.getAuthorizer() == null && !authorizer.isUnsatisfied()) {
            mgr.setAuthorizer(authorizer.get());
        }
        if (mgr.getCacheManager() == null && !cacheManager.isUnsatisfied()) {
            mgr.setCacheManager(cacheManager.get());
        }
        if (mgr.getEventBus() == null && !eventBus.isUnsatisfied()) {
            mgr.setEventBus(eventBus.get());
        }
        if (mgr.getSubjectDAO() == null && !subjectDAO.isUnsatisfied()) {
            mgr.setSubjectDAO(subjectDAO.get());
        }
        if (mgr.getSubjectFactory() == null && !subjectFactory.isUnsatisfied()) {
            mgr.setSubjectFactory(subjectFactory.get());
        } else if (mgr.getSubjectFactory() == null) {
            try {
                mgr.setSubjectFactory(SubjectFactory.class.cast(Load.load("org.apache.shiro.web.mgt.DefaultWebSubjectFactory", DefaultSubjectFactory.class).newInstance()));
            } catch (final IllegalAccessException e) {
                throw new IllegalStateException(e);
            } catch (final InstantiationException e) {
                throw new IllegalStateException(e);
            }
        }
        if (mgr.getSessionManager() == null && !sessionManager.isUnsatisfied()) {
            mgr.setSessionManager(sessionManager.get());
        }
        if (mgr.getRememberMeManager() == null && !rememberMeManager.isUnsatisfied()) {
            mgr.setRememberMeManager(rememberMeManager.get());
        }
        securityManagerEvent.fire(manager); // to customize it through an observer
        return manager;
    }
}
