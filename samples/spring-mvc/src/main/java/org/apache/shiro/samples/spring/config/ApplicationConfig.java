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
package org.apache.shiro.samples.spring.config;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.samples.spring.BootstrapDataPopulator;
import org.apache.shiro.samples.spring.DefaultSampleManager;
import org.apache.shiro.samples.spring.realm.SaltAwareJdbcRealm;
import org.apache.shiro.spring.config.ShiroAnnotationProcessorConfiguration;
import org.apache.shiro.spring.config.ShiroBeanConfiguration;
import org.apache.shiro.spring.remoting.SecureRemoteInvocationExecutor;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroRequestMappingConfig;
import org.apache.shiro.spring.web.config.ShiroWebConfiguration;
import org.apache.shiro.spring.web.config.ShiroWebFilterConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

import static org.apache.shiro.web.filter.mgt.DefaultFilter.anon;

/**
 * Application bean definitions.
 */
@Configuration
@PropertySource("classpath:application.properties")
@Import({ShiroBeanConfiguration.class,
        ShiroAnnotationProcessorConfiguration.class,
        ShiroWebConfiguration.class,
        ShiroWebFilterConfiguration.class,
        JspViewsConfig.class,
        RemotingServletConfig.class,
        ShiroRequestMappingConfig.class})
@ComponentScan("org.apache.shiro.samples.spring")
public class ApplicationConfig {


    /**
     *Populates the sample database with sample users and roles.
     * @param dataSource
     * @return
     */
    @Bean
    protected BootstrapDataPopulator bootstrapDataPopulator(DataSource dataSource) {
        BootstrapDataPopulator populator =new BootstrapDataPopulator();
        populator.setDataSource(dataSource);
        return populator;
    }


    /**
     * Used by the SecurityManager to access security data (users, roles, etc).
     * Many other realm implementations can be used too (PropertiesRealm,
     * LdapRealm, etc.
     * @param dataSource
     * @return
     */
    @Bean
    protected SaltAwareJdbcRealm jdbcRealm(DataSource dataSource) {

        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("SHA-256");
        credentialsMatcher.setStoredCredentialsHexEncoded(false);

        SaltAwareJdbcRealm jdbcRealm = new SaltAwareJdbcRealm();
        jdbcRealm.setName("jdbcRealm");
        jdbcRealm.setCredentialsMatcher(credentialsMatcher);
        jdbcRealm.setDataSource(dataSource);

        return jdbcRealm;
    }


    /**
     * Let's use some enterprise caching support for better performance.  You can replace this with any enterprise
     * caching framework implementation that you like (Terracotta+Ehcache, Coherence, GigaSpaces, etc
     *
     *
     * @return
     */
    @Bean
    protected EhCacheManager cacheManager() {

        EhCacheManager ehCacheManager = new EhCacheManager();

        // Set a net.sf.ehcache.CacheManager instance here if you already have one.
        // If not, a new one will be creaed with a default config:
        // ehCacheManager.setCacheManager(...);

        // If you don't have a pre-built net.sf.ehcache.CacheManager instance to inject, but you want
        // a specific Ehcache configuration to be used, specify that here.  If you don't, a default
        //will be used.:
        // ehCacheManager.setCacheManagerConfigFile("classpath:some/path/to/ehcache.xml");

        return ehCacheManager;
    }

    /**
     * Secure Spring remoting:  Ensure any Spring Remoting method invocations can be associated
     * with a Subject for security checks.
     * @param securityManager
     * @return
     */
    @Bean
    protected SecureRemoteInvocationExecutor secureRemoteInvocationExecutor(SecurityManager securityManager) {

        SecureRemoteInvocationExecutor executor = new SecureRemoteInvocationExecutor();
        executor.setSecurityManager(securityManager);

        return executor;
    }


    /**
     * Simulated business-tier "Manager", not Shiro related, just an example
     * @return
     */
    @Bean
    protected DefaultSampleManager sampleManager() {
        return new DefaultSampleManager();
    }

    /**
     * Sample RDBMS data source that would exist in any application - not Shiro related.
     * @return
     */
    @Bean
    protected DriverManagerDataSource dataSource() {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
        dataSource.setUrl("jdbc:hsqldb:mem:shiro-spring");
        dataSource.setUsername("sa");

        return dataSource;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
//        chainDefinition.addPathDefinition("/login.html", "authc"); // need to accept POSTs from the login form
//        chainDefinition.addPathDefinition("/logout", "logout");


        chainDefinition.addPathDefinition("/favicon.ico", "anon");
        chainDefinition.addPathDefinition("/logo.png", "anon");
        chainDefinition.addPathDefinition("/shiro.css", "anon");
        chainDefinition.addPathDefinition("/s/login", "anon");
        chainDefinition.addPathDefinition("/*.jar", "anon"); //allow WebStart to pull the jars for the swing app
        chainDefinition.addPathDefinition("/remoting/**", "anon"); // protected using SecureRemoteInvocationExecutor
        chainDefinition.addPathDefinition("/**", "authc");


        return chainDefinition;
    }


}
