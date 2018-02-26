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
package org.apache.shiro.guice.web;

import java.util.*;

import javax.servlet.Filter;
import javax.servlet.ServletContext;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.env.Environment;
import org.apache.shiro.guice.ShiroModule;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.filter.authc.AnonymousFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.filter.authz.PortFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.filter.authz.SslFilter;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.session.NoSessionCreationFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;

import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.name.Names;
import com.google.inject.servlet.ServletModule;

/**
 * Sets up Shiro lifecycles within Guice, enables the injecting of Shiro objects, and binds a default
 * {@link org.apache.shiro.web.mgt.WebSecurityManager}, {@link org.apache.shiro.mgt.SecurityManager} and {@link org.apache.shiro.session.mgt.SessionManager}.  At least one realm must be added by
 * using {@link #bindRealm() bindRealm}.
 * <p/>
 * Also provides for the configuring of filter chains and binds a {@link org.apache.shiro.web.filter.mgt.FilterChainResolver} with that information.
 */
public abstract class ShiroWebModule extends ShiroModule {
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<AnonymousFilter> ANON = Key.get(AnonymousFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<FormAuthenticationFilter> AUTHC = Key.get(FormAuthenticationFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<BasicHttpAuthenticationFilter> AUTHC_BASIC = Key.get(BasicHttpAuthenticationFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<NoSessionCreationFilter> NO_SESSION_CREATION = Key.get(NoSessionCreationFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<LogoutFilter> LOGOUT = Key.get(LogoutFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<PermissionsAuthorizationFilter> PERMS = Key.get(PermissionsAuthorizationFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<PortFilter> PORT = Key.get(PortFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<HttpMethodPermissionFilter> REST = Key.get(HttpMethodPermissionFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<RolesAuthorizationFilter> ROLES = Key.get(RolesAuthorizationFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<SslFilter> SSL = Key.get(SslFilter.class);
    @SuppressWarnings({"UnusedDeclaration"})
    public static final Key<UserFilter> USER = Key.get(UserFilter.class);


    static final String NAME = "SHIRO";

    /**
     * We use a LinkedHashMap here to ensure that iterator order is the same as add order.  This is important, as the
     * FilterChainResolver uses iterator order when searching for a matching chain.
     */
    private final Map<String, FilterConfig<? extends Filter>[]> filterChains = new LinkedHashMap<String, FilterConfig<? extends Filter>[]>();
    private final ServletContext servletContext;

    public ShiroWebModule(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public static void bindGuiceFilter(Binder binder) {
        binder.install(guiceFilterModule());
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public static void bindGuiceFilter(final String pattern, Binder binder) {
        binder.install(guiceFilterModule(pattern));
    }

    public static ServletModule guiceFilterModule() {
        return guiceFilterModule("/*");
    }

    public static ServletModule guiceFilterModule(final String pattern) {
        return new ServletModule() {
            @Override
            protected void configureServlets() {
                filter(pattern).through(GuiceShiroFilter.class);
            }
        };
    }

    @Override
    protected final void configureShiro() {
        bindBeanType(TypeLiteral.get(ServletContext.class), Key.get(ServletContext.class, Names.named(NAME)));
        bind(Key.get(ServletContext.class, Names.named(NAME))).toInstance(this.servletContext);
        bindWebSecurityManager(bind(WebSecurityManager.class));
        bindWebEnvironment(bind(WebEnvironment.class));
        bind(GuiceShiroFilter.class).asEagerSingleton();
        expose(GuiceShiroFilter.class);

        this.configureShiroWeb();

        bind(FilterChainResolver.class).toProvider(new FilterChainResolverProvider(setupFilterChainConfigs()));
    }

    private Map<String, Key<? extends Filter>[]> setupFilterChainConfigs() {

        // loop through and build a map of Filter Key -> Map<Path, Config>
        Map<Key<? extends Filter>, Map<String, String>> filterToPathToConfig = new HashMap<Key<? extends Filter>, Map<String, String>>();

        // At the same time build a map to return with Path -> Key[]
        Map<String, Key<? extends Filter>[]> resultConfigMap = new LinkedHashMap<String, Key<? extends Filter>[]>();

        for (Map.Entry<String, FilterConfig<? extends Filter>[]> filterChain : filterChains.entrySet()) {

            String path = filterChain.getKey();

            // collect the keys used for this path
            List<Key<? extends Filter>> keysForPath = new ArrayList<Key<? extends Filter>>();

            for (int i = 0; i < filterChain.getValue().length; i++) {
                FilterConfig<? extends Filter> filterConfig = filterChain.getValue()[i];

                Key<? extends Filter> key = filterConfig.getKey();
                String config = filterConfig.getConfigValue();

                // initialize key in filterToPathToConfig, if it doesn't exist
                if (filterToPathToConfig.get(key) == null) {
                	// Fix for SHIRO-621: REST filter bypassing matched path
                    filterToPathToConfig.put((key), new LinkedHashMap<String, String>());
                }
                // now set the value
                filterToPathToConfig.get(key).put(path, config);

                // Config error if someone configured a non PathMatchingFilter with a config value
                if (StringUtils.hasText(config) && !PathMatchingFilter.class.isAssignableFrom(key.getTypeLiteral().getRawType())) {
                    throw new ConfigurationException("Config information requires a PathMatchingFilter - can't apply to " + key.getTypeLiteral().getRawType());
                }

                // store the key in keysForPath
                keysForPath.add(key);
            }

            // map the current path to all of its Keys
            resultConfigMap.put(path, keysForPath.toArray(new Key[keysForPath.size()]));
        }

        // now we find only the PathMatchingFilter and configure bindings
        // non PathMatchingFilter, can be loaded with the default provider via the class name
        for (Key<? extends Filter> key : filterToPathToConfig.keySet()) {
            if (PathMatchingFilter.class.isAssignableFrom(key.getTypeLiteral().getRawType())) {
                bindPathMatchingFilter(castToPathMatching(key), filterToPathToConfig.get(key));
            }
            else {
                bind(key);
            }
        }

        return resultConfigMap;
    }


    private <T extends PathMatchingFilter> void bindPathMatchingFilter(Key<T> filterKey, Map<String, String> configs) {
        bind(filterKey).toProvider(new PathMatchingFilterProvider<T>(filterKey, configs)).asEagerSingleton();
    }

    @SuppressWarnings({"unchecked"})
    private Key<? extends PathMatchingFilter> castToPathMatching(Key<? extends Filter> key) {
        return (Key<? extends PathMatchingFilter>) key;
    }

    protected abstract void configureShiroWeb();

    @SuppressWarnings({"unchecked"})
    @Override
    protected final void bindSecurityManager(AnnotatedBindingBuilder<? super SecurityManager> bind) {
        bind.to(WebSecurityManager.class); // SHIRO-435
    }

    /**
     * Binds the security manager.  Override this method in order to provide your own security manager binding.
     * <p/>
     * By default, a {@link org.apache.shiro.web.mgt.DefaultWebSecurityManager} is bound as an eager singleton.
     *
     * @param bind
     */
    protected void bindWebSecurityManager(AnnotatedBindingBuilder<? super WebSecurityManager> bind) {
        try {
            bind.toConstructor(DefaultWebSecurityManager.class.getConstructor(Collection.class)).asEagerSingleton();
        } catch (NoSuchMethodException e) {
            throw new ConfigurationException("This really shouldn't happen.  Either something has changed in Shiro, or there's a bug in ShiroModule.", e);
        }
    }

    /**
     * Binds the session manager.  Override this method in order to provide your own session manager binding.
     * <p/>
     * By default, a {@link org.apache.shiro.web.session.mgt.DefaultWebSessionManager} is bound as an eager singleton.
     *
     * @param bind
     */
    @Override
    protected void bindSessionManager(AnnotatedBindingBuilder<SessionManager> bind) {
        bind.to(ServletContainerSessionManager.class).asEagerSingleton();
    }

    @Override
    protected final void bindEnvironment(AnnotatedBindingBuilder<Environment> bind) {
        bind.to(WebEnvironment.class); // SHIRO-435
    }

    protected void bindWebEnvironment(AnnotatedBindingBuilder<? super WebEnvironment> bind) {
        bind.to(WebGuiceEnvironment.class).asEagerSingleton();
    }

    protected final void addFilterChain(String pattern, Key<? extends Filter> key) {
        // check for legacy API
        if (key instanceof FilterConfigKey) {
            addLegacyFilterChain(pattern, (FilterConfigKey) key);
        }
        else {
            addFilterChain(pattern, new FilterConfig<Filter>((Key<Filter>) key, ""));
        }
    }

    /**
     * Maps 'n' number of <code>filterConfig</code>s to a specific path pattern.<BR/>
     * For example, a path of '/my_private_resource/**' to 'filterConfig(AUTHC)' would require
     * any resource under the path '/my_private_resource' would be processed through the {@link FormAuthenticationFilter}.
     *
     * @param pattern URL patter to be mapped to a FilterConfig, e.g. '/my_private-path/**'
     * @param filterConfigs FilterConfiguration representing the Filter and config to be used when processing resources on <code>pattern</code>.
     * @since 1.4
     */
    protected final void addFilterChain(String pattern, FilterConfig<? extends Filter>... filterConfigs) {
        filterChains.put(pattern, filterConfigs);
    }

    /**
     * Builds a FilterConfig from a Filer and configuration String
     * @param baseKey The Key of the Filter class to be used.
     * @param <T> A Servlet Filter class.
     * @return A FilterConfig used to map a String path to this configuration.
     * @since 1.4
     */
    protected static <T extends Filter> FilterConfig<T> filterConfig(Key<T> baseKey, String configValue) {
        return new FilterConfig<T>(baseKey, configValue);
    }

    /**
     * Builds a FilterConfig from a Filer and configuration String
     * @param baseKey The Key of the Filter class to be used.
     * @param <T> A Servlet Filter class.
     * @return A FilterConfig used to map a String path to this configuration.
     * @since 1.4
     */
    protected static <T extends Filter> FilterConfig<T> filterConfig(Key<T> baseKey) {
        return filterConfig(baseKey, "");
    }

    /**
     * Builds a FilterConfig from a Filer and configuration String
     * @param typeLiteral The TyleLiteral of the filter key to be used.
     * @param configValue the configuration used.
     * @param <T> A Servlet Filter class.
     * @return A FilterConfig used to map a String path to this configuration.
     * @since 1.4
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected static <T extends Filter> FilterConfig<T> filterConfig(TypeLiteral<T> typeLiteral, String configValue) {
        return filterConfig(Key.get(typeLiteral), configValue);
    }

    /**
     * Builds a FilterConfig from a Filer and configuration String
     * @param type The filter to be used.
     * @param configValue the configuration used.
     * @param <T> A Servlet Filter class.
     * @return A FilterConfig used to map a String path to this configuration.
     * @since 1.4
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected static <T extends Filter> FilterConfig<T> filterConfig(Class<T> type, String configValue) {
        return filterConfig(Key.get(type), configValue);
    }


    /**
     * Filter configuration which pairs a Filter class with its configuration used on a path.
     * @param <T> The Servlet Filter class.
     * @since 1.4
     */
    public static class FilterConfig<T extends Filter> {
        private Key<T> key;
        private String configValue;

        private FilterConfig(Key<T> key, String configValue) {
            super();
            this.key = key;
            this.configValue = configValue;
        }

        public Key<T> getKey() {
            return key;
        }

        public String getConfigValue() {
            return configValue;
        }
    }







    // legacy methods


    static boolean isGuiceVersion3() {
        try {
            Class.forName("com.google.inject.multibindings.MapKey");
            return false;
        } catch (ClassNotFoundException e) {
            return true;
        }
    }

    private void addLegacyFilterChain(String pattern, FilterConfigKey filterConfigKey) {

        FilterConfig<Filter> filterConfig = new FilterConfig<Filter>(filterConfigKey.getKey(), filterConfigKey.getConfigValue());
        addFilterChain(pattern, filterConfig);
    }

    /**
     * Adds a filter chain to the shiro configuration.
     * <p/>
     * NOTE: If the provided key is for a subclass of {@link org.apache.shiro.web.filter.PathMatchingFilter}, it will be registered with a proper
     * provider.
     *
     * @param pattern
     * @param keys
     */
    @SuppressWarnings({"UnusedDeclaration"})
    @Deprecated
    protected final void addFilterChain(String pattern, Key<? extends Filter>... keys) {

        // We need to extract the keys and FilterConfigKey and convert to the new format.

        FilterConfig[] filterConfigs = new FilterConfig[keys.length];
        for (int ii = 0; ii < keys.length; ii++) {
            Key<? extends Filter> key = keys[ii];
            // If this is a path matching filter, we need to remember the config
            if (key instanceof FilterConfigKey) {
                // legacy config
                FilterConfigKey legacyKey = (FilterConfigKey) key;
                filterConfigs[ii] = new FilterConfig(legacyKey.getKey(), legacyKey.getConfigValue());
            }
            else {
                // Some other type of Filter key, no config
                filterConfigs[ii] = new FilterConfig(key, "");
            }
        }

        filterChains.put(pattern, filterConfigs);
    }

    @Deprecated
    protected static <T extends PathMatchingFilter> Key<T> config(Key<T> baseKey, String configValue) {

        if( !isGuiceVersion3()) {
            throw new ConfigurationException("Method ShiroWebModule.config(Key<? extends PathMatchingFilter>, String configValue), is not supported when using Guice 4+");
        }

        return new FilterConfigKey<T>(baseKey, configValue);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    @Deprecated
    protected static <T extends PathMatchingFilter> Key<T> config(TypeLiteral<T> typeLiteral, String configValue) {
        return config(Key.get(typeLiteral), configValue);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    @Deprecated
    protected static <T extends PathMatchingFilter> Key<T> config(Class<T> type, String configValue) {
        return config(Key.get(type), configValue);
    }

    @Deprecated
    private static class FilterConfigKey<T extends PathMatchingFilter> extends Key<T> {
        private Key<T> key;
        private String configValue;

        private FilterConfigKey(Key<T> key, String configValue) {
            super();
            this.key = key;
            this.configValue = configValue;
        }

        public Key<T> getKey() {
            return key;
        }

        public String getConfigValue() {
            return configValue;
        }
    }

}
