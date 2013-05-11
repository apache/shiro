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
package org.apache.shiro.web.env;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniFactorySupport;
import org.apache.shiro.io.ResourceUtils;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * {@link WebEnvironment} implementation configured by an {@link Ini} instance or {@code Ini} resource locations.
 *
 * @since 1.2
 */
public class IniWebEnvironment extends ResourceBasedWebEnvironment implements Initializable, Destroyable {

    public static final String DEFAULT_WEB_INI_RESOURCE_PATH = "/WEB-INF/shiro.ini";

    private static final Logger log = LoggerFactory.getLogger(IniWebEnvironment.class);

    /**
     * The Ini that configures this WebEnvironment instance.
     */
    private Ini ini;

    /**
     * Initializes this instance by resolving any potential (explicit or resource-configured) {@link Ini}
     * configuration and calling {@link #configure() configure} for actual instance configuration.
     */
    public void init() {
        Ini ini = getIni();

        String[] configLocations = getConfigLocations();

        if (log.isWarnEnabled() && !CollectionUtils.isEmpty(ini) &&
                configLocations != null && configLocations.length > 0) {
            log.warn("Explicit INI instance has been provided, but configuration locations have also been " +
                    "specified.  The {} implementation does not currently support multiple Ini config, but this may " +
                    "be supported in the future. Only the INI instance will be used for configuration.",
                    IniWebEnvironment.class.getName());
        }

        if (CollectionUtils.isEmpty(ini)) {
            log.debug("Checking any specified config locations.");
            ini = getSpecifiedIni(configLocations);
        }

        if (CollectionUtils.isEmpty(ini)) {
            log.debug("No INI instance or config locations specified.  Trying default config locations.");
            ini = getDefaultIni();
        }

        if (CollectionUtils.isEmpty(ini)) {
            String msg = "Shiro INI configuration was either not found or discovered to be empty/unconfigured.";
            throw new ConfigurationException(msg);
        }

        setIni(ini);

        configure();
    }

    protected void configure() {

        this.objects.clear();

        WebSecurityManager securityManager = createWebSecurityManager();
        setWebSecurityManager(securityManager);

        FilterChainResolver resolver = createFilterChainResolver();
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }
    }

    protected Ini getSpecifiedIni(String[] configLocations) throws ConfigurationException {

        Ini ini = null;

        if (configLocations != null && configLocations.length > 0) {

            if (configLocations.length > 1) {
                log.warn("More than one Shiro .ini config location has been specified.  Only the first will be " +
                        "used for configuration as the {} implementation does not currently support multiple " +
                        "files.  This may be supported in the future however.", IniWebEnvironment.class.getName());
            }

            //required, as it is user specified:
            ini = createIni(configLocations[0], true);
        }

        return ini;
    }

    protected Ini getDefaultIni() {

        Ini ini = null;

        String[] configLocations = getDefaultConfigLocations();
        if (configLocations != null) {
            for (String location : configLocations) {
                ini = createIni(location, false);
                if (!CollectionUtils.isEmpty(ini)) {
                    log.debug("Discovered non-empty INI configuration at location '{}'.  Using for configuration.",
                            location);
                    break;
                }
            }
        }

        return ini;
    }

    /**
     * Creates an {@link Ini} instance reflecting the specified path, or {@code null} if the path does not exist and
     * is not required.
     * <p/>
     * If the path is required and does not exist or is empty, a {@link ConfigurationException} will be thrown.
     *
     * @param configLocation the resource path to load into an {@code Ini} instance.
     * @param required       if the path must exist and be converted to a non-empty {@link Ini} instance.
     * @return an {@link Ini} instance reflecting the specified path, or {@code null} if the path does not exist and
     *         is not required.
     * @throws ConfigurationException if the path is required but results in a null or empty Ini instance.
     */
    protected Ini createIni(String configLocation, boolean required) throws ConfigurationException {

        Ini ini = null;

        if (configLocation != null) {
            ini = convertPathToIni(configLocation, required);
        }
        if (required && CollectionUtils.isEmpty(ini)) {
            String msg = "Required configuration location '" + configLocation + "' does not exist or did not " +
                    "contain any INI configuration.";
            throw new ConfigurationException(msg);
        }

        return ini;
    }

    protected FilterChainResolver createFilterChainResolver() {

        FilterChainResolver resolver = null;

        Ini ini = getIni();

        if (!CollectionUtils.isEmpty(ini)) {
            //only create a resolver if the 'filters' or 'urls' sections are defined:
            Ini.Section urls = ini.getSection(IniFilterChainResolverFactory.URLS);
            Ini.Section filters = ini.getSection(IniFilterChainResolverFactory.FILTERS);
            if (!CollectionUtils.isEmpty(urls) || !CollectionUtils.isEmpty(filters)) {
                //either the urls section or the filters section was defined.  Go ahead and create the resolver:
                IniFilterChainResolverFactory factory = new IniFilterChainResolverFactory(ini, this.objects);
                resolver = factory.getInstance();
            }
        }

        return resolver;
    }

    protected WebSecurityManager createWebSecurityManager() {
        WebIniSecurityManagerFactory factory;
        Ini ini = getIni();
        if (CollectionUtils.isEmpty(ini)) {
            factory = new WebIniSecurityManagerFactory();
        } else {
            factory = new WebIniSecurityManagerFactory(ini);
        }

        WebSecurityManager wsm = (WebSecurityManager)factory.getInstance();

        //SHIRO-306 - get beans after they've been created (the call was before the factory.getInstance() call,
        //which always returned null.
        Map<String, ?> beans = factory.getBeans();
        if (!CollectionUtils.isEmpty(beans)) {
            this.objects.putAll(beans);
        }

        return wsm;
    }

    /**
     * Returns an array with two elements, {@code /WEB-INF/shiro.ini} and {@code classpath:shiro.ini}.
     *
     * @return an array with two elements, {@code /WEB-INF/shiro.ini} and {@code classpath:shiro.ini}.
     */
    protected String[] getDefaultConfigLocations() {
        return new String[]{
                DEFAULT_WEB_INI_RESOURCE_PATH,
                IniFactorySupport.DEFAULT_INI_RESOURCE_PATH
        };
    }

    /**
     * Converts the specified file path to an {@link Ini} instance.
     * <p/>
     * If the path does not have a resource prefix as defined by {@link org.apache.shiro.io.ResourceUtils#hasResourcePrefix(String)}, the
     * path is expected to be resolvable by the {@code ServletContext} via
     * {@link javax.servlet.ServletContext#getResourceAsStream(String)}.
     *
     * @param path     the path of the INI resource to load into an INI instance.
     * @param required if the specified path must exist
     * @return an INI instance populated based on the given INI resource path.
     */
    private Ini convertPathToIni(String path, boolean required) {

        //TODO - this logic is ugly - it'd be ideal if we had a Resource API to polymorphically encaspulate this behavior

        Ini ini = null;

        if (StringUtils.hasText(path)) {
            InputStream is = null;

            //SHIRO-178: Check for servlet context resource and not only resource paths:
            if (!ResourceUtils.hasResourcePrefix(path)) {
                is = getServletContextResourceStream(path);
            } else {
                try {
                    is = ResourceUtils.getInputStreamForPath(path);
                } catch (IOException e) {
                    if (required) {
                        throw new ConfigurationException(e);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to load optional path '" + path + "'.", e);
                        }
                    }
                }
            }
            if (is != null) {
                ini = new Ini();
                ini.load(is);
            } else {
                if (required) {
                    throw new ConfigurationException("Unable to load resource path '" + path + "'");
                }
            }
        }

        return ini;
    }

    //TODO - this logic is ugly - it'd be ideal if we had a Resource API to polymorphically encaspulate this behavior
    private InputStream getServletContextResourceStream(String path) {
        InputStream is = null;

        path = WebUtils.normalize(path);
        ServletContext sc = getServletContext();
        if (sc != null) {
            is = sc.getResourceAsStream(path);
        }

        return is;
    }

    /**
     * Returns the {@code Ini} instance reflecting this WebEnvironment's configuration.
     *
     * @return the {@code Ini} instance reflecting this WebEnvironment's configuration.
     */
    public Ini getIni() {
        return this.ini;
    }

    /**
     * Allows for configuration via a direct {@link Ini} instance instead of via
     * {@link #getConfigLocations() config locations}.
     * <p/>
     * If the specified instance is null or empty, the fallback/default resource-based configuration will be used.
     *
     * @param ini the ini instance to use for creation.
     */
    public void setIni(Ini ini) {
        this.ini = ini;
    }
}
