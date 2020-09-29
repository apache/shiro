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

import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.config.AbstractShiroConfiguration;
import org.apache.shiro.spring.web.ShiroUrlPathHelper;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.springframework.beans.factory.annotation.Value;

/**
 * @since 1.4.0
 */
public class AbstractShiroWebConfiguration extends AbstractShiroConfiguration {

    @Value("#{ @environment['shiro.sessionManager.sessionIdCookieEnabled'] ?: true }")
    protected boolean sessionIdCookieEnabled;

    @Value("#{ @environment['shiro.sessionManager.sessionIdUrlRewritingEnabled'] ?: false }")
    protected boolean sessionIdUrlRewritingEnabled;

    @Value("#{ @environment['shiro.userNativeSessionManager'] ?: false }")
    protected boolean useNativeSessionManager;


    // Session Cookie info

    @Value("#{ @environment['shiro.sessionManager.cookie.name'] ?: T(org.apache.shiro.web.servlet.ShiroHttpSession).DEFAULT_SESSION_ID_NAME }")
    protected String sessionIdCookieName;

    @Value("#{ @environment['shiro.sessionManager.cookie.maxAge'] ?: T(org.apache.shiro.web.servlet.SimpleCookie).DEFAULT_MAX_AGE }")
    protected int sessionIdCookieMaxAge;

    @Value("#{ @environment['shiro.sessionManager.cookie.domain'] ?: null }")
    protected String sessionIdCookieDomain;

    @Value("#{ @environment['shiro.sessionManager.cookie.path'] ?: null }")
    protected String sessionIdCookiePath;

    @Value("#{ @environment['shiro.sessionManager.cookie.secure'] ?: false }")
    protected boolean sessionIdCookieSecure;

    @Value("#{ @environment['shiro.sessionManager.cookie.sameSite'] ?: T(org.apache.shiro.web.servlet.Cookie.SameSiteOptions).LAX  }")
    protected Cookie.SameSiteOptions sessionIdCookieSameSite;


    // RememberMe Cookie info

    @Value("#{ @environment['shiro.rememberMeManager.cookie.name'] ?: T(org.apache.shiro.web.mgt.CookieRememberMeManager).DEFAULT_REMEMBER_ME_COOKIE_NAME }")
    protected String rememberMeCookieName;

    @Value("#{ @environment['shiro.rememberMeManager.cookie.maxAge'] ?: T(org.apache.shiro.web.servlet.Cookie).ONE_YEAR }")
    protected int rememberMeCookieMaxAge;

    @Value("#{ @environment['shiro.rememberMeManager.cookie.domain'] ?: null }")
    protected String rememberMeCookieDomain;

    @Value("#{ @environment['shiro.rememberMeManager.cookie.path'] ?: null }")
    protected String rememberMeCookiePath;

    @Value("#{ @environment['shiro.rememberMeManager.cookie.secure'] ?: false }")
    protected boolean rememberMeCookieSecure;

    @Value("#{ @environment['shiro.rememberMeManager.cookie.sameSite'] ?: T(org.apache.shiro.web.servlet.Cookie.SameSiteOptions).LAX }")
    protected Cookie.SameSiteOptions rememberMeSameSite;


    protected SessionManager nativeSessionManager() {
        DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager();
        webSessionManager.setSessionIdCookieEnabled(sessionIdCookieEnabled);
        webSessionManager.setSessionIdUrlRewritingEnabled(sessionIdUrlRewritingEnabled);
        webSessionManager.setSessionIdCookie(sessionCookieTemplate());

        webSessionManager.setSessionFactory(sessionFactory());
        webSessionManager.setSessionDAO(sessionDAO());
        webSessionManager.setDeleteInvalidSessions(sessionManagerDeleteInvalidSessions);

        return webSessionManager;
    }

    protected Cookie sessionCookieTemplate() {
        return buildCookie(
                sessionIdCookieName,
                sessionIdCookieMaxAge,
                sessionIdCookiePath,
                sessionIdCookieDomain,
                sessionIdCookieSecure,
                sessionIdCookieSameSite);
    }

    protected Cookie rememberMeCookieTemplate() {
        return buildCookie(
                rememberMeCookieName,
                rememberMeCookieMaxAge,
                rememberMeCookiePath,
                rememberMeCookieDomain,
                rememberMeCookieSecure,
                rememberMeSameSite);
    }

    protected Cookie buildCookie(String name, int maxAge, String path, String domain, boolean secure) {
        return buildCookie(name, maxAge, path, domain, secure, Cookie.SameSiteOptions.LAX);
    }

    protected Cookie buildCookie(String name, int maxAge, String path, String domain, boolean secure, Cookie.SameSiteOptions sameSiteOption) {
        Cookie cookie = new SimpleCookie(name);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        cookie.setPath(path);
        cookie.setDomain(domain);
        cookie.setSecure(secure);
        cookie.setSameSite(sameSiteOption);

        return cookie;
    }

    @Override
    protected SessionManager sessionManager() {
        if (useNativeSessionManager) {
            return nativeSessionManager();
        }
        return new ServletContainerSessionManager();
    }

    @Override
    protected RememberMeManager rememberMeManager() {
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookieTemplate());
        return cookieRememberMeManager;
    }

    @Override
    protected SubjectFactory subjectFactory() {
        return new DefaultWebSubjectFactory();
    }

    @Override
    protected SessionStorageEvaluator sessionStorageEvaluator() {
        return new DefaultWebSessionStorageEvaluator();
    }

    @Override
    protected SessionsSecurityManager createSecurityManager() {

        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setSubjectDAO(subjectDAO());
        securityManager.setSubjectFactory(subjectFactory());
        securityManager.setRememberMeManager(rememberMeManager());

        return securityManager;
    }

    protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        chainDefinition.addPathDefinition("/**", "authc");
        return chainDefinition;
    }

    protected ShiroUrlPathHelper shiroUrlPathHelper() {
        return new ShiroUrlPathHelper();
    }
}
