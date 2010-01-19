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
package org.apache.shiro.spring.web;

import org.apache.shiro.config.Ini;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Nameable;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.servlet.IniShiroFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanPostProcessor;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@link org.springframework.beans.factory.FactoryBean FactoryBean} to be used in Spring-based web applications.
 * <h4>Usage</h4>
 * Declare a DelegatingFilterProxy in {@code web.xml}:
 * <pre>
 * &lt;filter&gt;
 *   &lt;filter-name&gt;<b>shiroFilter</b>&lt;/filter-name&gt;
 *   &lt;filter-class&gt;org.springframework.web.filter.DelegatingFilterProxy&lt;filter-class&gt;
 * &lt;/filter&gt;
 * </pre>
 * Then, in your spring XML file that defines your web ApplicationContext:
 * <pre>
 * <p/>
 * </pre>
 *
 * @author The Apache Shiro Project (shiro-dev@incubator.apache.org)
 * @since 1.0
 */
public class ShiroFilterFactoryBean implements FactoryBean, BeanPostProcessor {

    private static transient final Logger log = LoggerFactory.getLogger(ShiroFilterFactoryBean.class);

    private SecurityManager securityManager;

    private Map<String, Filter> filters;

    private Map<String, String> filterChainDefinitionMap; //urlPathExpression_to_comma-delimited-filter-chain-definition

    private AbstractShiroFilter instance;

    public ShiroFilterFactoryBean() {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChainDefinitionMap = new LinkedHashMap<String, String>(); //order matters!
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /**
     * Returns the filterName-to-Filter map of filters available for reference when defining filter chain definitions.
     * All filter chain definitions will reference filters by the names in this map (i.e. the keys).
     * <p/>
     * Note that this map is often a merging of Shiro's default Filters ({@code authc}
     * This map will contain all
     * Note that most end-users will not need configure in spring the corresponding {@link #setFilters} method
     *
     * @return the filterName-to-Filter map of filters available for reference when defining filter chain definitions.
     */
    public Map<String, Filter> getFilters() {
        return filters;
    }

    /**
     * Sets the filterName-to-Filter map of filters available for reference when creating
     * {@link #setFilterChainDefinitionMap(java.util.Map) filter chain definitions}.
     * <p/>
     * <b>Note:</b> This property is optional:  this {@code FactoryBean} implementation will discover all beans in the
     * web application context that implement the {@link Filter} interface and automatically add them to this filter
     * map under their bean name.
     * <p/>
     * For example, just defining this bean in a web Spring XML application context:
     * <pre>
     * &lt;bean id=&quot;myFilter&quot; class=&quot;com.class.that.implements.javax.servlet.Filter&quot;&gt;
     * ...
     * &lt;/bean&gt;</pre>
     * Will automatically place that bean into this Filters map under the key '<b>myFilter</b>'.
     *
     * @param filters the optional filterName-to-Filter map of filters available for reference when creating
     *                {@link #setFilterChainDefinitionMap (java.util.Map) filter chain definitions}.
     */
    public void setFilters(Map<String, Filter> filters) {
        this.filters = filters;
    }

    /**
     * Returns the chainName-to-chainDefinition map of chain definitions to use for creating filter chains intercepted
     * by the Shiro Filter.  Each map entry should conform to the format defined by the
     * {@link FilterChainManager#createChain(String, String)} JavaDoc, where the map key is the chain name (i.e. URL
     * path expression) and the map value is the comma-delimited string chain definition.
     *
     * @return he chainName-to-chainDefinition map of chain definitions to use for creating filter chains intercepted
     *         by the Shiro Filter.
     */
    public Map<String, String> getFilterChainDefinitionMap() {
        return filterChainDefinitionMap;
    }

    /**
     * Sets the chainName-to-chainDefinition map of chain definitions to use for creating filter chains intercepted
     * by the Shiro Filter.  Each map entry should conform to the format defined by the
     * {@link FilterChainManager#createChain(String, String)} JavaDoc, where the map key is the chain name (i.e. URL
     * path expression) and the map value is the comma-delimited string chain definition.
     *
     * @param filterChainDefinitionMap the chainName-to-chainDefinition map of chain definitions to use for creating
     *                               filter chains intercepted by the Shiro Filter.
     */
    public void setFilterChainDefinitionMap(Map<String, String> filterChainDefinitionMap) {
        this.filterChainDefinitionMap = filterChainDefinitionMap;
    }

    public void setFilterChainDefinitions(String definitions) {
        Ini ini = new Ini();
        ini.load(definitions);
        //did they explicitly state a 'urls' section?  Not necessary, but just in case:
        Ini.Section section = ini.getSection(IniFilterChainResolverFactory.URLS);
        if ( CollectionUtils.isEmpty(section) ) {
            //no urls section.  Since this _is_ a urls chain definition property, just assume the
            //default section contains only the definitions:
            section = ini.getSection(Ini.DEFAULT_SECTION_NAME);
        }
        setFilterChainDefinitionMap(section);
    }

    public Object getObject() throws Exception {
        if (instance == null) {
            instance = (AbstractShiroFilter)createInstance();
        }
        return instance;
    }

    public Class getObjectType() {
        return AbstractShiroFilter.class;
    }

    public boolean isSingleton() {
        return true;
    }

    protected FilterChainManager createFilterChainManager() {

        DefaultFilterChainManager manager = new DefaultFilterChainManager();

        //Apply the acquired and/or configured filters:
        Map<String, Filter> filters = getFilters();
        if (!CollectionUtils.isEmpty(filters)) {
            for (Map.Entry<String, Filter> entry : filters.entrySet()) {
                String name = entry.getKey();
                Filter filter = entry.getValue();
                if (filter instanceof Nameable) {
                    ((Nameable) filter).setName(name);
                }
                //'init' argument is false, since Spring-configured filters should be initialized
                //in Spring (i.e. 'init-method=blah') or implement InitializingBean:
                manager.addFilter(name, filter, false);
            }
        }

        //build up the chains:
        Map<String, String> chains = getFilterChainDefinitionMap();
        if (!CollectionUtils.isEmpty(chains)) {
            for (Map.Entry<String, String> entry : chains.entrySet()) {
                String url = entry.getKey();
                String chainDefinition = entry.getValue();
                manager.createChain(url, chainDefinition);
            }
        }

        return manager;
    }

    /**
     * This implementation:
     * <ol>
     * <li>Ensures the {@link #setSecurityManager(org.apache.shiro.mgt.SecurityManager) securityManager} property
     * has been set</li>
     * <li>Creates a {@link FilterChainManager} instance that reflects the configured
     * {@link #setFilters(java.util.Map) filters} and
     * {@link #setFilterChainDefinitionMap(java.util.Map) filter chain definitions}</li>
     * <li>Wraps the FilterChainManager with a suitable
     * {@link org.apache.shiro.web.filter.mgt.FilterChainResolver FilterChainResolver} since the Shiro Filter
     * implementations do not know of {@code FilterChainManager}s</li>
     * <li>Sets both the {@code SecurityManager} and {@code FilterChainResolver} instances on a new Shiro Filter
     * instance and returns that filter instance.</li>
     * </ol>
     *
     * @return a new Shiro Filter reflecting any configured filters and filter chain definitions.
     * @throws Exception if there is a problem creating the ShiroFilter instance.
     */
    protected Object createInstance() throws Exception {

        log.debug("Creating Shiro Filter instance.");

        SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            String msg = "SecurityManager property must be set.";
            throw new BeanInitializationException(msg);
        }

        FilterChainManager manager = createFilterChainManager();

        //Expose the constructed FilterChainManager by first wrapping it in a
        // FilterChainResolver implementation. The ShiroFilter implementations
        // do not know about FilterChainManagers - only resolvers:
        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
        chainResolver.setFilterChainManager(manager);

        //Now create a ShiroFilter and apply the acquired SecurityManager and built
        //FilterChainResolver.  It doesn't matter that the ShiroFilter instance is an INI filter
        //here - we're just using it because it is a concrete ShiroFilter instance that accepts
        //injection of the SecurityManager and FilterChainResolver:
        IniShiroFilter shiroFilter = new IniShiroFilter();
        shiroFilter.setSecurityManager(securityManager);
        shiroFilter.setFilterChainResolver(chainResolver);

        return shiroFilter;
    }

    /**
     * Inspects a bean, and if it implements the {@link Filter} interface, automatically adds that filter
     * instance to the internal {@link #setFilters(java.util.Map) filters map} that will be referenced
     * later during filter chain construction.
     */
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof Filter) {
            log.debug("Found filter chain candidate filter '{}'", beanName);
            getFilters().put(beanName, (Filter) bean);
        } else {
            log.trace("Ignoring non-Filter bean '{}'", beanName);
        }
        return bean;
    }

    /**
     * Does nothing - only exists to satisfy the BeanPostProcessor interface and immediately returns the
     * {@code bean} argument.
     */
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }
}
