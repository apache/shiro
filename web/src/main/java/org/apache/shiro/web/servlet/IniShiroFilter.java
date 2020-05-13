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
package org.apache.shiro.web.servlet;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.ini.IniFactorySupport;
import org.apache.shiro.lang.io.ResourceUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Map;

/**
 * <h1>Deprecated</h1>
 * This filter has been deprecated as of Shiro 1.2 in favor of using the {@link ShiroFilter} in {@code web.xml} instead.
 * See the {@link ShiroFilter} JavaDoc for usage.
 * <p/>
 * ======================
 * <p/>
 * Servlet Filter that configures and enables all Shiro functions within a web application by using the
 * <a href="http://en.wikipedia.org/wiki/INI_file">INI</a> configuration format.
 * <p/>
 * The actual INI configuration contents are not covered here, but instead in Shiro's
 * <a href="http://shiro.apache.org/configuration.html">Configuration Documentation</a> and additional web-specific
 * <a href="http://shiro.apache.org/web.html">Web Documentation</a>.
 * <h2>Usage</h2>
 * <h3>Default</h3>
 * By default, the simplest filter declaration expects a {@code shiro.ini} resource to be located at
 * {@code /WEB-INF/shiro.ini}, or, if not there, falls back to checking the root of the classpath
 * (i.e. {@code classpath:shiro.ini}):
 * <pre>
 * &lt;filter&gt;
 *     &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 *     &lt;filter-class&gt;org.apache.shiro.web.servlet.IniShiroFilter&lt;/filter-class&gt;
 * &lt;/filter&gt;
 * </pre>
 * <h3>Custom Path</h3>
 * If you want the INI configuration to be somewhere other than {@code /WEB-INF/shiro.ini} or
 * {@code classpath:shiro.ini}, you may specify an alternate location via the {@code configPath init-param}:
 * <pre>
 * &lt;filter&gt;
 *     &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 *     &lt;filter-class&gt;org.apache.shiro.web.servlet.IniShiroFilter&lt;/filter-class&gt;
 *     &lt;init-param&gt;
 *         &lt;param-name&gt;configPath&lt;/param-name&gt;
 *         &lt;param-value&gt;/WEB-INF/someFile.ini&lt;/param-value&gt;
 *     &lt;/init-param&gt;
 * &lt;/filter&gt;
 * </pre>
 * Unqualified (schemeless or 'non-prefixed') paths are assumed to be {@code ServletContext} resource paths, resolvable
 * via {@link javax.servlet.ServletContext#getResourceAsStream(String) ServletContext#getResourceAsStream}.
 * <p/>
 * Non-ServletContext resources may be loaded from qualified locations by specifying prefixes indicating the source,
 * e.g. {@code file:}, {@code url:}, and {@code classpath:}.  See the
 * {@link ResourceUtils#getInputStreamForPath(String)} JavaDoc for more.
 * <h3>Inline</h3>
 * For relatively simple environments, you can embed the INI config directly inside the filter declaration with
 * the {@code config init-param}:
 * <pre>
 * &lt;filter&gt;
 *     &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 *     &lt;filter-class&gt;org.apache.shiro.web.servlet.IniShiroFilter&lt;/filter-class&gt;
 *     &lt;init-param&gt;
 *         &lt;param-name&gt;config&lt;/param-name&gt;
 *         &lt;param-value&gt;
 *             #INI config goes here...
 *      &lt;/param-value&gt;
 *     &lt;/init-param&gt;
 * &lt;/filter&gt;
 * </pre>
 * Although this is typically not recommended because any Shiro configuration changes would contribute to version control
 * 'noise' in the web.xml file.
 * <p/>
 * When creating the shiro.ini configuration itself, please see Shiro's
 * <a href="http://shiro.apache.org/configuration.html">Configuration Documentation</a> and
 * <a href="http://shiro.apache.org/web.html">Web Documentation</a>.
 *
 * @see <a href="http://shiro.apache.org/configuration.html">Apache Shiro INI Configuration</a>
 * @see <a href="http://shiro.apache.org/web.html">Apache Shiro Web Documentation</a>
 * @since 1.0
 * @deprecated in 1.2 in favor of using the {@link ShiroFilter}
 */
@Deprecated
public class IniShiroFilter extends AbstractShiroFilter {

    public static final String CONFIG_INIT_PARAM_NAME = "config";
    public static final String CONFIG_PATH_INIT_PARAM_NAME = "configPath";

    public static final String DEFAULT_WEB_INI_RESOURCE_PATH = "/WEB-INF/shiro.ini";

    private static final Logger log = LoggerFactory.getLogger(IniShiroFilter.class);

    private String config;
    private String configPath;

    public IniShiroFilter() {
    }

    /**
     * Returns the actual INI configuration text to use to build the {@link SecurityManager} and
     * {@link FilterChainResolver} used by the web application or {@code null} if the
     * {@link #getConfigPath() configPath} should be used to load a fallback INI source.
     * <p/>
     * This value is {@code null} by default, but it will be automatically set to the value of the
     * '{@code config}' {@code init-param} if it exists in the {@code FilterConfig} provided by the servlet
     * container at startup.
     *
     * @return the actual INI configuration text to use to build the {@link SecurityManager} and
     *         {@link FilterChainResolver} used by the web application or {@code null} if the
     *         {@link #getConfigPath() configPath} should be used to load a fallback INI source.
     */
    public String getConfig() {
        return this.config;
    }

    /**
     * Sets the actual INI configuration text to use to build the {@link SecurityManager} and
     * {@link FilterChainResolver} used by the web application.  If this value is {@code null}, the
     * {@link #getConfigPath() configPath} will be checked to see if a .ini file should be loaded instead.
     * <p/>
     * This value is {@code null} by default, but it will be automatically set to the value of the
     * '{@code config}' {@code init-param} if it exists in the {@code FilterConfig} provided by the servlet
     * container at startup.
     *
     * @param config the actual INI configuration text to use to build the {@link SecurityManager} and
     *               {@link FilterChainResolver} used by the web application.
     */
    public void setConfig(String config) {
        this.config = config;
    }

    /**
     * Returns the config path to be used to load a .ini file for configuration if a configuration is
     * not specified via the {@link #getConfig() config} attribute.
     * <p/>
     * This value is {@code null} by default, but it will be automatically set to the value of the
     * '{@code configPath}' {@code init-param} if it exists in the {@code FilterConfig} provided by the servlet
     * container at startup.
     *
     * @return the config path to be used to load a .ini file for configuration if a configuration is
     *         not specified via the {@link #getConfig() config} attribute.
     */
    public String getConfigPath() {
        return configPath;
    }

    /**
     * Sets the config path to be used to load a .ini file for configuration if a configuration is
     * not specified via the {@link #getConfig() config} attribute.
     * <p/>
     * This value is {@code null} by default, but it will be automatically set to the value of the
     * '{@code configPath}' {@code init-param} if it exists in the {@code FilterConfig} provided by the servlet
     * container at startup.
     *
     * @param configPath the config path to be used to load a .ini file for configuration if a configuration is
     *                   not specified via the {@link #getConfig() config} attribute.
     */
    public void setConfigPath(String configPath) {
        this.configPath = StringUtils.clean(configPath);
    }

    public void init() throws Exception {
        applyInitParams();
        configure();
    }

    protected void applyInitParams() throws Exception {
        String config = getInitParam(CONFIG_INIT_PARAM_NAME);
        if (config != null) {
            setConfig(config);
        }
        String configPath = getInitParam(CONFIG_PATH_INIT_PARAM_NAME);
        if (configPath != null) {
            setConfigPath(configPath);
        }
    }

    protected void configure() throws Exception {
        Ini ini = loadIniFromConfig();

        if (CollectionUtils.isEmpty(ini)) {
            log.info("Null or empty configuration specified via 'config' init-param.  " +
                    "Checking path-based configuration.");
            ini = loadIniFromPath();
        }
        //added for SHIRO-178:
        if (CollectionUtils.isEmpty(ini)) {
            log.info("Null or empty configuration specified via '" + CONFIG_INIT_PARAM_NAME + "' or '" +
                    CONFIG_PATH_INIT_PARAM_NAME + "' filter parameters.  Trying the default " +
                    DEFAULT_WEB_INI_RESOURCE_PATH + " file.");
            ini = getServletContextIniResource(DEFAULT_WEB_INI_RESOURCE_PATH);
        }
        //although the preferred default is /WEB-INF/shiro.ini per SHIRO-178, keep this
        //for backwards compatibility:
        if (CollectionUtils.isEmpty(ini)) {
            log.info("Null or empty configuration specified via '" + CONFIG_INIT_PARAM_NAME + "' or '" +
                    CONFIG_PATH_INIT_PARAM_NAME + "' filter parameters.  Trying the default " +
                    IniFactorySupport.DEFAULT_INI_RESOURCE_PATH + " file.");
            ini = IniFactorySupport.loadDefaultClassPathIni();
        }

        Map<String, ?> objects = applySecurityManager(ini);
        applyFilterChainResolver(ini, objects);
    }

    protected Ini loadIniFromConfig() {
        Ini ini = null;
        String config = getConfig();
        if (config != null) {
            ini = convertConfigToIni(config);
        }
        return ini;
    }

    protected Ini loadIniFromPath() {
        Ini ini = null;
        String path = getConfigPath();
        if (path != null) {
            ini = convertPathToIni(path);
        }
        return ini;
    }

    protected Map<String, ?> applySecurityManager(Ini ini) {
        WebIniSecurityManagerFactory factory;
        if (CollectionUtils.isEmpty(ini)) {
            factory = new WebIniSecurityManagerFactory();
        } else {
            factory = new WebIniSecurityManagerFactory(ini);
        }

        // Create the security manager and check that it implements WebSecurityManager.
        // Otherwise, it can't be used with the filter.
        SecurityManager securityManager = factory.getInstance();
        if (!(securityManager instanceof WebSecurityManager)) {
            String msg = "The configured security manager is not an instance of WebSecurityManager, so " +
                    "it can not be used with the Shiro servlet filter.";
            throw new ConfigurationException(msg);
        }

        setSecurityManager((WebSecurityManager) securityManager);

        return factory.getBeans();
    }

    protected void applyFilterChainResolver(Ini ini, Map<String, ?> defaults) {
        if (ini == null || ini.isEmpty()) {
            //nothing to use to create the resolver, just return
            //(the AbstractShiroFilter allows a null resolver, in which case the original FilterChain is
            // always used).
            return;
        }

        //only create a resolver if the 'filters' or 'urls' sections are defined:
        Ini.Section urls = ini.getSection(IniFilterChainResolverFactory.URLS);
        Ini.Section filters = ini.getSection(IniFilterChainResolverFactory.FILTERS);
        if ((urls != null && !urls.isEmpty()) || (filters != null && !filters.isEmpty())) {
            //either the urls section or the filters section was defined.  Go ahead and create the resolver
            //and set it:
            IniFilterChainResolverFactory filterChainResolverFactory = new IniFilterChainResolverFactory(ini, defaults);
            filterChainResolverFactory.setFilterConfig(getFilterConfig());
            FilterChainResolver resolver = filterChainResolverFactory.getInstance();
            setFilterChainResolver(resolver);
        }
    }

    protected Ini convertConfigToIni(String config) {
        Ini ini = new Ini();
        ini.load(config);
        return ini;
    }

    /**
     * Returns the INI instance reflecting the specified servlet context resource path or {@code null} if no
     * resource was found.
     *
     * @param servletContextPath the servlet context resource path of the INI file to load
     * @return the INI instance reflecting the specified servlet context resource path or {@code null} if no
     *         resource was found.
     * @since 1.2
     */
    protected Ini getServletContextIniResource(String servletContextPath) {
        String path = WebUtils.normalize(servletContextPath);
        if (getServletContext() != null) {
            InputStream is = getServletContext().getResourceAsStream(path);
            if (is != null) {
                Ini ini = new Ini();
                ini.load(is);
                if (CollectionUtils.isEmpty(ini)) {
                    log.warn("ServletContext INI resource '" + servletContextPath + "' exists, but it did not contain " +
                            "any data.");
                }
                return ini;
            }
        }
        return null;
    }

    /**
     * Converts the specified file path to an {@link Ini} instance.
     * <p/>
     * If the path does not have a resource prefix as defined by {@link ResourceUtils#hasResourcePrefix(String)}, the
     * path is expected to be resolvable by the {@code ServletContext} via
     * {@link javax.servlet.ServletContext#getResourceAsStream(String)}.
     *
     * @param path the path of the INI resource to load into an INI instance.
     * @return an INI instance populated based on the given INI resource path.
     */
    protected Ini convertPathToIni(String path) {

        Ini ini = new Ini();

        //SHIRO-178: Check for servlet context resource and not
        //only resource paths:
        if (!ResourceUtils.hasResourcePrefix(path)) {
            ini = getServletContextIniResource(path);
            if (ini == null) {
                String msg = "There is no servlet context resource corresponding to configPath '" + path + "'  If " +
                        "the resource is located elsewhere (not immediately resolveable in the servlet context), " +
                        "specify an appropriate classpath:, url:, or file: resource prefix accordingly.";
                throw new ConfigurationException(msg);
            }
        } else {
            //normal resource path - load as usual:
            ini.loadFromPath(path);
        }

        return ini;
    }
}
