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
package org.apache.shiro.web.config;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniFactorySupport;
import org.apache.shiro.config.ReflectionBuilder;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Factory;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import java.util.Map;

/**
 * A {@link Factory} that creates {@link FilterChainResolver} instances based on {@link Ini} configuration.
 *
 * @author The Apache Shiro Project (shiro-dev@incubator.apache.org)
 * @since 1.0
 */
public class IniFilterChainResolverFactory extends IniFactorySupport<FilterChainResolver> {

    public static final String FILTERS = "filters";
    public static final String URLS = "urls";

    private static transient final Logger log = LoggerFactory.getLogger(IniFilterChainResolverFactory.class);

    private FilterConfig filterConfig;

    public IniFilterChainResolverFactory() {
        super();
    }

    public IniFilterChainResolverFactory(Ini ini) {
        super(ini);
    }

    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    protected FilterChainResolver createInstance(Ini ini) {
        FilterChainResolver filterChainResolver = createDefaultInstance();
        if (filterChainResolver instanceof PathMatchingFilterChainResolver) {
            PathMatchingFilterChainResolver resolver = (PathMatchingFilterChainResolver) filterChainResolver;
            FilterChainManager manager = resolver.getFilterChainManager();
            buildChains(manager, ini);
        }
        return filterChainResolver;
    }

    protected FilterChainResolver createDefaultInstance() {
        FilterConfig filterConfig = getFilterConfig();
        if (filterConfig != null) {
            return new PathMatchingFilterChainResolver(filterConfig);
        } else {
            return new PathMatchingFilterChainResolver();
        }
    }

    protected void buildChains(FilterChainManager manager, Ini ini) {
        //filters section:
        Ini.Section section = ini.getSection(FILTERS);
        Map<String, Filter> filters = getFilters(section, manager.getFilters());

        //add the filters to the manager:
        registerFilters(filters, manager);

        //urls section:
        section = ini.getSection(URLS);
        createChains(section, manager);
    }

    protected void registerFilters(Map<String, Filter> filters, FilterChainManager manager) {
        if (!CollectionUtils.isEmpty(filters)) {
            boolean init = getFilterConfig() != null; //only call filter.init if there is a FilterConfig available
            for (Map.Entry<String, Filter> entry : filters.entrySet()) {
                String name = entry.getKey();
                Filter filter = entry.getValue();
                manager.addFilter(name, filter, init);
            }
        }
    }

    @SuppressWarnings({"unchecked"})
    protected Map<String, Filter> getFilters(Map<String, String> section, Map<String, Filter> defaultFilters) {

        Map<String, Filter> filters = defaultFilters;

        if (!CollectionUtils.isEmpty(section)) {
            ReflectionBuilder builder = new ReflectionBuilder(defaultFilters);
            Map<String, ?> built = builder.buildObjects(section);
            assertFilters(built);
            filters = (Map<String, Filter>) built;
        }

        return filters;
    }

    protected void assertFilters(Map<String, ?> map) {
        if (!CollectionUtils.isEmpty(map)) {
            for (Map.Entry<String, ?> entry : map.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                assertFilter(key, value);
            }
        }
    }

    protected void assertFilter(String name, Object o) throws ConfigurationException {
        if (!(o instanceof Filter)) {
            String msg = "[" + FILTERS + "] section specified a filter named '" + name + "', which does not " +
                    "implement the " + Filter.class.getName() + " interface.  Only Filter implementations may be " +
                    "defined.";
            throw new ConfigurationException(msg);
        }
    }

    protected void createChains(Map<String, String> urls, FilterChainManager manager) {
        if (CollectionUtils.isEmpty(urls)) {
            if (log.isDebugEnabled()) {
                log.debug("No urls to process.");
            }
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Before url processing.");
        }

        for (Map.Entry<String, String> entry : urls.entrySet()) {
            String path = entry.getKey();
            String value = entry.getValue();
            manager.createChain(path, value);
        }
    }
}
