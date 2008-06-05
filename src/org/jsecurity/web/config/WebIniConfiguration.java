/*
 * Copyright 2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.config;

import org.jsecurity.config.ConfigurationException;
import org.jsecurity.config.IniConfiguration;
import org.jsecurity.config.ReflectionBuilder;
import org.jsecurity.mgt.RealmSecurityManager;
import static org.jsecurity.util.StringUtils.split;
import org.jsecurity.web.DefaultWebSecurityManager;
import org.jsecurity.web.interceptor.PathConfigWebInterceptor;
import org.jsecurity.web.interceptor.WebInterceptor;
import org.jsecurity.web.interceptor.authc.BasicHttpAuthenticationWebInterceptor;
import org.jsecurity.web.interceptor.authc.FormAuthenticationWebInterceptor;
import org.jsecurity.web.interceptor.authz.PermissionsAuthorizationWebInterceptor;
import org.jsecurity.web.interceptor.authz.RolesAuthorizationWebInterceptor;
import org.jsecurity.web.servlet.WebInterceptorFilter;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since Jun 1, 2008 11:02:44 PM
 */
public class WebIniConfiguration extends IniConfiguration implements WebConfiguration {

    public static final String INTERCEPTORS = "interceptors";
    public static final String URLS = "urls";

    protected FilterConfig filterConfig = null;

    protected List<Filter> filters = null;

    public WebIniConfiguration() {
    }

    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public List<Filter> getFilters() {
        return this.filters;
    }

    protected RealmSecurityManager newSecurityManagerInstance() {
        return new DefaultWebSecurityManager();
    }

    /**
     * 1.  First builds the interceptor and/or filter instances.
     * 2.  Applys url mappings to these interceptors and/or filters
     * 3.  Creates a collection of Filter objects that will be used by the JSecurityFilter.
     *
     * @param sections
     */
    protected void afterSecurityManagerSet(Map<String, Map<String, String>> sections) {
        //interceptors section:
        Map<String, String> section = sections.get(INTERCEPTORS);
        Map<String, Object> interceptors = getWebInterceptors(section);

        //urls section:
        section = sections.get(URLS);
        interceptors = applyUrls(interceptors, section);

        this.filters = convertToFilters(interceptors);
    }

    protected Map<String, Object> getWebInterceptors(Map<String, String> interceptorsSection) {

        Map<String, Object> interceptors = buildDefaultInterceptors();

        if (interceptorsSection != null && !interceptorsSection.isEmpty()) {
            ReflectionBuilder builder = new ReflectionBuilder(interceptors);
            interceptors = builder.buildObjects(interceptorsSection);
        }

        return interceptors;
    }

    public Map<String, Object> buildDefaultInterceptors() {
        Map<String, Object> interceptors = new LinkedHashMap<String, Object>();
        interceptors.put("authc", new FormAuthenticationWebInterceptor());
        interceptors.put("authcBasic", new BasicHttpAuthenticationWebInterceptor());
        interceptors.put("roles", new RolesAuthorizationWebInterceptor());
        interceptors.put("perms", new PermissionsAuthorizationWebInterceptor());
        return interceptors;
    }

    public Map<String, Object> applyUrls(Map<String, Object> interceptors, Map<String, String> urls) {

        if (urls == null || urls.isEmpty() ) {
            if (log.isDebugEnabled()) {
                log.debug("No urls to process.");
            }
            return interceptors;
        }

        if (log.isTraceEnabled()) {
            log.trace("Before url processing.");
        }

        for (Map.Entry<String, String> entry : urls.entrySet()) {
            String path = entry.getKey();
            String value = entry.getValue();

            if (log.isDebugEnabled()) {
                log.debug("Processing path [" + path + "] with value [" + value + "]");
            }

            //parse the value by tokenizing it to get the resulting interceptor-specific config entries
            //
            //e.g. for a value of
            //
            //     "authc, roles[admin,user], perms[file:edit]"
            //
            // the resulting token array would equal
            //
            //     { "authc", "roles[admin,user]", "perms[file:edit]" }
            //
            String[] interceptorTokens = split(value, ',', '[', ']', true, true);

            //each token is specific to each web interceptor.
            //strip the name and extract any interceptor-specific config between brackets [ ]
            for (String token : interceptorTokens) {
                String[] nameAndConfig = token.split("\\[", 2);
                String name = nameAndConfig[0];
                String config = null;

                if (nameAndConfig.length == 2) {
                    config = nameAndConfig[1];
                    //if there was an open bracket, there was a close bracket, so strip it too:
                    config = config.substring(0, config.length() - 1);
                }

                //now we have the interceptor name, path and (possibly null) path-specific config.  Let's apply them:
                Object interceptor = interceptors.get(name);
                if (interceptor instanceof PathConfigWebInterceptor) {
                    if (log.isDebugEnabled()) {
                        log.debug("Applying path [" + path + "] to interceptor [" + name + "] " +
                                "with config [" + config + "]");
                    }
                    ((PathConfigWebInterceptor) interceptor).processPathConfig(path, config);
                }
            }
        }

        return interceptors;
    }

    protected List<Filter> convertToFilters(Map<String, Object> interceptors) throws ConfigurationException {

        if (interceptors == null || interceptors.isEmpty()) {
            return null;
        }

        if (log.isDebugEnabled()) {
            log.debug("Interceptors configured: " + interceptors.size());
        }

        List<Filter> filters = new ArrayList<Filter>(interceptors.size());

        for (String key : interceptors.keySet()) {
            Object value = interceptors.get(key);
            Filter filter = null;

            if (value instanceof Filter) {
                filter = (Filter) value;
            } else if (value instanceof WebInterceptor) {
                WebInterceptor interceptor = (WebInterceptor) value;
                WebInterceptorFilter wiFilter = new WebInterceptorFilter();
                wiFilter.setWebInterceptor(interceptor);
                filter = wiFilter;
            } else if (value != null) {
                String msg = "filtersAndInterceptors collection contains an object of type [" +
                        value.getClass().getName() + "].  This instance does not implement " +
                        Filter.class.getName() + " or the " + WebInterceptor.class.getName() + " interfaces.  " +
                        "Only filters and interceptors may be configured.";
                throw new ConfigurationException(msg);
            }

            if (filter != null) {
                try {
                    filter.init(getFilterConfig());
                } catch (ServletException e) {
                    throw new ConfigurationException(e);
                }
                filters.add(filter);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Configured and/or wrapped " + filters.size() + " filters.");
        }

        return filters;
    }
}
