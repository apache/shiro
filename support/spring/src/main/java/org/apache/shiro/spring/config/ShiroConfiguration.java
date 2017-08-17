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
package org.apache.shiro.spring.config;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.mgt.*;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.util.List;

/**
 * @since 1.4.0
 */
@Configuration
@Import({ShiroBeanConfiguration.class})
public class ShiroConfiguration extends AbstractShiroConfiguration {


    @Bean
    @Override
    protected SessionsSecurityManager securityManager(List<Realm> realms) {
        return super.securityManager(realms);
    }

    @Bean
    @Override
    protected SessionManager sessionManager() {
        return super.sessionManager();
    }

    @Bean
    @Override
    protected SubjectDAO subjectDAO() {
        return super.subjectDAO();
    }

    @Bean
    @Override
    protected SessionStorageEvaluator sessionStorageEvaluator() {
        return super.sessionStorageEvaluator();
    }

    @Bean
    @Override
    protected SubjectFactory subjectFactory() {
        return super.subjectFactory();
    }

    @Bean
    @Override
    protected SessionFactory sessionFactory() {
        return super.sessionFactory();
    }

    @Bean
    @Override
    protected SessionDAO sessionDAO() {
        return super.sessionDAO();
    }

    @Bean
    @Override
    protected Authorizer authorizer() {
        return super.authorizer();
    }

    @Bean
    @Override
    protected AuthenticationStrategy authenticationStrategy() {
        return super.authenticationStrategy();
    }

    @Bean
    @Override
    protected Authenticator authenticator() {
        return super.authenticator();
    }

    @Bean
    @Override
    protected RememberMeManager rememberMeManager() {
        return super.rememberMeManager();
    }
}
