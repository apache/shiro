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
package org.apache.shiro.spring.config.web.autoconfigure;

import java.util.List;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.config.Ini;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.config.web.autoconfigure.exception.NoRealmBeanConfiguredException;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.apache.shiro.web.servlet.Cookie;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @since 1.4.0
 */
@Configuration
@ConditionalOnProperty(name = "shiro.web.enabled", matchIfMissing = true)
public class ShiroWebAutoConfiguration extends AbstractShiroWebConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected AuthenticationStrategy authenticationStrategy() {
        return super.authenticationStrategy();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected Authenticator authenticator() {
        return super.authenticator();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected Authorizer authorizer() {
        return super.authorizer();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SubjectDAO subjectDAO() {
        return super.subjectDAO();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SessionStorageEvaluator sessionStorageEvaluator() {
        return super.sessionStorageEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SessionFactory sessionFactory() {
        return super.sessionFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SessionDAO sessionDAO() {
        return super.sessionDAO();
    }

    @Bean
    @ConditionalOnMissingBean(name = "sessionCookieTemplate")
    @Override
    protected Cookie sessionCookieTemplate() {
        return super.sessionCookieTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected RememberMeManager rememberMeManager() {
        return super.rememberMeManager();
    }

    @Bean
    @ConditionalOnMissingBean(name = "rememberMeCookieTemplate")
    @Override
    protected Cookie rememberMeCookieTemplate() {
        return super.rememberMeCookieTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SubjectFactory subjectFactory() {
        return super.subjectFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SessionManager sessionManager() {
        return super.sessionManager();
    }

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected SessionsSecurityManager securityManager(List<Realm> realms) {
        return super.securityManager(realms);
    }
    
    @Bean
    @ConditionalOnResource(resources = "classpath:shiro.ini")
    protected Realm iniClasspathRealm() {
        Ini ini = Ini.fromResourcePath("classpath:shiro.ini");
        IniRealm iniRealm = new IniRealm( ini );
        return iniRealm;
    }
    
    @Bean
    @ConditionalOnResource(resources = "classpath:META-INF/shiro.ini")
    protected Realm iniMetaInfClasspathRealm() {
        Ini ini = Ini.fromResourcePath("classpath:META-INF/shiro.ini");
        IniRealm iniRealm = new IniRealm( ini );
        return iniRealm;
    }
    
    @Bean
    @ConditionalOnMissingBean(Realm.class)
    protected Realm missingRealm() {
        throw new NoRealmBeanConfiguredException();
    }

}
