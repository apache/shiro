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

import org.apache.shiro.config.Ini;
import org.apache.shiro.ini.IniFactorySupport;
import org.apache.shiro.ini.IniSecurityManagerFactory;
import org.apache.shiro.config.ogdl.ReflectionBuilder;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.Factory;
import org.apache.shiro.web.filter.mgt.DefaultFilter;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A {@link Factory} that creates {@link FilterChainResolver} instances based on {@link Ini} configuration.
 *
 * @since 1.0
 */
public class IniFilterChainResolverFactory extends IniFactorySupport<FilterChainResolver> {

    public static final String FILTERS = "filters";
    public static final String URLS = "urls";

    private static transient final Logger log = LoggerFactory.getLogger(IniFilterChainResolverFactory.class);

    private FilterConfig filterConfig;

    private List<String> globalFilters = Collections.singletonList(DefaultFilter.invalidRequest.name());

    public IniFilterChainResolverFactory() {
        super();
    }

    public IniFilterChainResolverFactory(Ini ini) {
        super(ini);
    }

    public IniFilterChainResolverFactory(Ini ini, Map<String, ?> defaultBeans) {
        this(ini);
        this.setDefaults(defaultBeans);
    }

    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public List<String> getGlobalFilters() {
        return globalFilters;
    }

    public void setGlobalFilters(List<String> globalFilters) {
        this.globalFilters = globalFilters;
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

        if (!CollectionUtils.isEmpty(section)) {
            String msg = "The [{}] section has been deprecated and will be removed in a future release!  Please " +
                    "move all object configuration (filters and all other objects) to the [{}] section.";
            log.warn(msg, FILTERS, IniSecurityManagerFactory.MAIN_SECTION_NAME);
        }

        Map<String, Object> defaults = new LinkedHashMap<String, Object>();

        Map<String, Filter> defaultFilters = manager.getFilters();

        //now let's see if there are any object defaults in addition to the filters
        //these can be used to configure the filters:
        //create a Map of objects to use as the defaults:
        if (!CollectionUtils.isEmpty(defaultFilters)) {
            defaults.putAll(defaultFilters);
        }
        //User-provided objects must come _after_ the default filters - to allow the user-provided
        //ones to override the default filters if necessary.
        Map<String, ?> defaultBeans = getDefaults();
        if (!CollectionUtils.isEmpty(defaultBeans)) {
            defaults.putAll(defaultBeans);
        }

        Map<String, Filter> filters = getFilters(section, defaults);

        //add the filters to the manager:
        registerFilters(filters, manager);

        manager.setGlobalFilters(getGlobalFilters());

        //urls section:
        section = ini.getSection(URLS);
        createChains(section, manager);

        // create the default chain, to match anything the path matching would have missed
        manager.createDefaultChain("/**"); // TODO this assumes ANT path matching
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

    protected Map<String, Filter> getFilters(Map<String, String> section, Map<String, ?> defaults) {

        Map<String, Filter> filters = extractFilters(defaults);

        if (!CollectionUtils.isEmpty(section)) {
            ReflectionBuilder builder = new ReflectionBuilder(defaults);
            Map<String, ?> built = builder.buildObjects(section);
            Map<String,Filter> sectionFilters = extractFilters(built);

            if (CollectionUtils.isEmpty(filters)) {
                filters = sectionFilters;
            } else {
                if (!CollectionUtils.isEmpty(sectionFilters)) {
                    filters.putAll(sectionFilters);
                }
            }
        }

        return filters;
    }

    private Map<String, Filter> extractFilters(Map<String, ?> objects) {
        if (CollectionUtils.isEmpty(objects)) {
            return null;
        }
        Map<String, Filter> filterMap = new LinkedHashMap<String, Filter>();
        for (Map.Entry<String, ?> entry : objects.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Filter) {
                filterMap.put(key, (Filter) value);
            }
        }
        return filterMap;
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
