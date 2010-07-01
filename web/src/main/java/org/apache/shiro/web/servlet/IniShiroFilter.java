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
import org.apache.shiro.config.IniFactorySupport;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Main Servlet Filter that configures and enables all Shiro functions within a web application by using the
 * <a href="http://en.wikipedia.org/wiki/INI_file">INI</a> configuration format.
 * <p/>
 * The following is a fully commented example that documents how to configure it:
 * <pre>&lt;filter&gt;
 * &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 * &lt;filter-class&gt;org.apache.shiro.web.servlet.IniShiroFilter&lt;/filter-class&gt;
 * &lt;init-param&gt;&lt;param-name&gt;config&lt;/param-name&gt;&lt;param-value&gt;
 * #
 * #NOTE:  This config looks pretty long - but its not - its only a few lines of actual config.
 * #       Everything else is just heavily commented to explain things in-depth. Feel free to delete any
 * #       comments that you don't want to read from your own configuration ;)
 * #
 * # Any commented values below that _don't_ start with 'example.pkg' are Shiro's defaults.  If you want to change any
 * # values on those lines, you only need to uncomment the lines you want to change.
 * #
 * [main]
 * # The 'main' section defines Shiro-wide configuration.
 * #
 * # Each section's configuration is essentially an object graph definition in a .properties style (name/value pair)
 * # format.  The beans defined would be those that are used to construct the application's SecurityManager.  It is
 * # essentially 'poor man's' dependency injection via a .properties format.
 * #
 * # --- Defining Realms ---
 * #
 * # Any Realm defined here will automatically be injected into Shiro's default SecurityManager created at start up.
 * # For example:
 * #
 * # myRealm = example.pkg.security.MyRealm
 * #
 * # This would instantiate the example.pkg.security.MyRealm class with a default no-arg constructor and inject it into
 * # the SecurityManager.  More than one realm can be defined if needed.  You can create graphs and reference
 * # other beans ('$' bean reference notation) while defining Realms and other objects:
 * #
 * # <b>connectionFactory</b> = example.pkg.ConnectionFactory
 * # connectionFactory.driverClassName = a.jdbc.Driver
 * # connectionFactory.username = aUsername
 * # connectionFactory.password = aPassword
 * # connectionFactory.minConnections = 3
 * # connectionFactory.maxConnections = 10
 * # ... etc...
 * #
 * # myJdbcRealm = example.pkg.jdbc.MyJdbcRealm
 * # myJdbcRealm.connectionFactory = <b>$connectionFactory</b>
 * # ... etc ...
 * #
 * # --- Realm Factories ---
 * #
 * # If the INI style isn't robust enough for your needs, you also have the option of implementing the
 * # {@link org.apache.shiro.realm.RealmFactory org.apache.shiro.realm.RealmFactory} interface with more complex construction
 * # logic.  Then you can declare the implementation here instead.  The realms it returns will be injected in to the
 * # SecurityManager just as the individual Realms are.  For example:
 * #
 * # aRealmFactory = example.pkg.ClassThatImplementsRealmFactory
 * #
 * # --- SessionManager properties ---
 * #
 * # Except for Realms and RealmFactories, all other objects should be defined and set on the SecurityManager directly.
 * # The default 'securityManager' bean is an instance of {@link org.apache.shiro.web.mgt.DefaultWebSecurityManager}, so you
 * # can set any of its corresponding properties as necessary:
 * #
 * # someObject = some.fully.qualified.ClassName
 * # someObject.propertyN = foo
 * # ...
 * # securityManager.someObject = $someObject
 * #
 * # For example, if you wanted to change Shiro's default session mechanism, you can change the 'sessionMode' property.
 * # By default, Shiro's Session infrastructure in a web environment will use the
 * # Servlet container's HttpSession.  However, if you need to share session state across client types
 * # (e.g. Web MVC plus Java Web Start or Flash), or are doing distributed/shared Sessions for
 * # Single Sign On, HttpSessions aren't good enough.  You'll need to use Shiro's more powerful
 * # (and client-agnostic) session management.  You can enable this by uncommenting the following line
 * # and changing 'http' to 'native'
 * #
 * #securityManager.{@link org.apache.shiro.web.mgt.DefaultWebSecurityManager#setSessionMode(String) sessionMode} = http
 * #
 * [filters]
 * # This section defines the 'pool' of all Filters available to the url path definitions in the [urls] section below.
 * #
 * # The following commented values are already provided by Shiro by default and are immediately usable
 * # in the [urls] definitions below.  If you like, you may override any values by uncommenting only the lines
 * # you need to change.
 * #
 * # Each Filter is configured based on its functionality and/or protocol.  You should read each
 * # Filter's JavaDoc to fully understand what each does and how it works as well as how it would
 * # affect the user experience.
 * #
 * # Form-based Authentication filter:
 * #<a name="authc"></a>authc = {@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter}
 * #authc.{@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#setLoginUrl(String) loginUrl} = /login.jsp
 * #authc.{@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#setUsernameParam(String) usernameParam} = username
 * #authc.{@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#setPasswordParam(String) passwordParam} = password
 * #authc.{@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#setRememberMeParam(String) rememberMeParam} = rememberMe
 * #authc.{@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#setSuccessUrl(String) successUrl}  = /login.jsp
 * #authc.{@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#setFailureKeyAttribute(String) failureKeyAttribute} = {@link org.apache.shiro.web.filter.authc.FormAuthenticationFilter#DEFAULT_ERROR_KEY_ATTRIBUTE_NAME}
 * #
 * # Http BASIC Authentication filter:
 * #<a name="authcBasic"></a>authcBasic = {@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter}
 * #authcBasic.{@link org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter#setApplicationName(String) applicationName} = application
 * #
 * # Roles filter: requires the requesting user to have one or more roles for the request to continue.
 * # If they do not have the specified roles, they are redirected to the specified URL.
 * #<a name="roles"></a>roles = {@link org.apache.shiro.web.filter.authz.RolesAuthorizationFilter}
 * #roles.{@link org.apache.shiro.web.filter.authz.RolesAuthorizationFilter#setUnauthorizedUrl(String) unauthorizedUrl} =
 * # (note the above url is null by default, which will cause an HTTP 403 (Access Denied) response instead
 * # of redirecting to a page.  If you want to show a 'nice page' instead, you should specify that url.
 * #
 * # Permissions filter: requires the requesting user to have one or more permissions for the request to
 * # continue, and if they do not, redirects them to the specified URL.
 * #<a name="perms"></a>perms = {@link org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter}
 * #perms.{@link org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter#setUnauthorizedUrl(String) unauthorizedUrl} =
 * # (note the above url is null by default, which will cause an HTTP 403 (Access Denied) response instead
 * # of redirecting to a page.  If you want to show a 'nice page' instead, you should specify that url.  Many
 * # applications like to use the same url specified in roles.unauthorizedUrl above.
 * #
 * #
 * # Define your own filters here as you would any other object as described in the '[main]' section above (properties,
 * # $references, etc).  To properly handle url path matching (see the [urls] section below), your
 * # filter should extend the {@link org.apache.shiro.web.filter.PathMatchingFilter PathMatchingFilter} abstract class.
 * #
 * [urls]
 * # This section defines url path mappings.  Each mapping entry must be on a single line and conform to the
 * # following representation:
 * #
 * # ant_path_expression = path_specific_filter_chain_definition
 * #
 * # For any request that matches a specified path, the corresponding value defines a comma-delimited chain of
 * # filters to execute for that request.
 * #
 * # This is incredibly powerful in that you can define arbitrary filter chains for any given request pattern
 * # to greatly customize the security experience.
 * #
 * # The path_specific_filter_chain_definition must match the following format:
 * #
 * # filter1[optional_config1], filter2[optional_config2], ..., filterN[optional_configN]
 * #
 * # where 'filterN' is the name of an filter defined above in the [filters] section and
 * # '[optional_configN]' is an optional bracketed string that has meaning for that particular filter for
 * # _that particular path_.  If the filter does not need specific config for that url path, you may
 * # discard the brackets so filterN[] just becomes filterN.
 * #
 * # And because filter tokens define chains, order matters!  Define the tokens for each path pattern
 * # in the order you want them to filter (comma-delimited).
 * #
 * # Finally, each filter is free to handle the response however it wants if its necessary
 * # conditions are not met (redirect, HTTP error code, direct rendering, etc).  Otherwise, it is expected to allow
 * # the request to continue through the chain on to the final destination view.
 * #
 * # Examples:
 * #
 * # To illustrate chain configuration, look at the /account/** mapping below.  This says
 * # &quot;apply the above 'authcBasic' filter to any request matching the '/account/**' pattern&quot;.  Since the
 * # 'authcBasic' filter does not need any path-specific config, it doesn't have any config brackets [].
 * #
 * # The /remoting/** definition on the other hand uses the 'roles' and 'perms' filters which do use
 * # bracket notation.  That definition says:
 * #
 * # &quot;To access /remoting/** urls, ensure that the user is first authenticated ('authcBasic'), then ensure that user
 * # has the 'b2bClient' role, and then finally ensure that they have the 'remote:invoke:lan,wan' permission.&quot;
 * #
 * # (Note that because elements within brackets [ ] are comma-delimited themselves, we needed to quote any config
 * # value which may require a comma. If we didn't do that, the permission filter below would interpret
 * # the text between the brackets as two permissions: 'remote:invoke:lan' and 'wan' instead of the
 * # single desired 'remote:invoke:lan,wan' token.  So, you can use quotes wherever you need to escape internal
 * # commas.)
 * #
 * /account/** = <a href="#authcBasic">authcBasic</a>
 * /remoting/** = <a href="#authcBasic">authcBasic</a>, <a href="#roles">roles</a>[b2bClient], <a href="#perms">perms</a>["remote:invoke:lan,wan"]
 * &lt;/param-value&gt;&lt;/init-param&gt;
 * &lt;/filter&gt;
 * <p/>
 * &lt;filter-mapping&gt;
 *     &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 *     &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;</pre>
 *
 * @since 1.0
 */
public class IniShiroFilter extends AbstractShiroFilter {

    public static final String CONFIG_INIT_PARAM_NAME = "config";
    public static final String CONFIG_PATH_INIT_PARAM_NAME = "configPath";

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
        this.configPath = configPath;
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

    protected Ini convertPathToIni(String path) {
        Ini ini = new Ini();
        ini.loadFromPath(path);
        return ini;
    }
}
