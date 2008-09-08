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
package org.jsecurity.web.servlet;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.config.Configuration;
import org.jsecurity.config.ConfigurationException;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.util.ClassUtils;
import org.jsecurity.util.LifecycleUtils;
import static org.jsecurity.util.StringUtils.clean;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.DefaultWebSecurityManager;
import org.jsecurity.web.WebUtils;
import org.jsecurity.web.config.IniWebConfiguration;
import org.jsecurity.web.config.WebConfiguration;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.PropertyDescriptor;
import java.io.IOException;
import java.net.InetAddress;

/**
 * Main ServletFilter that configures and enables all JSecurity functions within a web application.
 *
 * The following is a fully commented example that documents how to configure it:
 *
 * <pre>&lt;filter&gt;
 * &lt;filter-name&gt;JSecurityFilter&lt;/filter-name&gt;
 * &lt;filter-class&gt;org.jsecurity.web.servlet.JSecurityFilter&lt;/filter-class&gt;
 * &lt;init-param&gt;&lt;param-name&gt;config&lt;/param-name&gt;&lt;param-value&gt;
 *
 * #NOTE:  This config looks pretty long - but its not - its only 5 lines of actual config.
 * #       Everything else is just heavily commented to explain things in-depth. Feel free to delete any
 * #       comments that you don't want to read from your own configuration ;)
 * #
 * # Any commented values below are JSecurity's defaults.  If you want to change any values, you only
 * # need to uncomment the lines you want to change.
 *
 * [main]
 * # The 'main' section defines JSecurity-wide configuration.
 * #
 * # Session Mode: By default, JSecurity's Session infrastructure in a web environment will use the
 * # Servlet container's HttpSession.  However, if you need to share session state across client types
 * # (e.g. Web MVC plus Java Web Start or Flash), or are doing distributed/shared Sessions for
 * # Single Sign On, HttpSessions aren't good enough.  You'll need to use JSecurity's more powerful
 * # (and client-agnostic) session management.  You can enable this by uncommenting the following line
 * # and changing 'http' to 'jsecurity'
 * #
 * #securityManager = {@link org.jsecurity.web.DefaultWebSecurityManager org.jsecurity.web.DefaultWebSecurityManager}
 * #securityManager.{@link org.jsecurity.web.DefaultWebSecurityManager#setSessionMode(String) sessionMode} = http
 *
 * [filters]
 * # This section defines the 'pool' of all Filters available to the url path definitions in the [urls] section below.
 * #
 * # The following commented values are already provided by JSecurity by default and are immediately usable
 * # in the [urls] definitions below.  If you like, you may override any values by uncommenting only the lines
 * # you need to change.
 * #
 * # Each Filter is configured based on its functionality and/or protocol.  You should read each
 * # Filter's JavaDoc to fully understand what each does and how it works as well as how it would
 * # affect the user experience.
 * #
 * # Form-based Authentication filter:
 * #<a name="authc"></a>authc = {@link org.jsecurity.web.filter.authc.FormAuthenticationFilter}
 * #authc.{@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#setLoginUrl(String) url} = /login.jsp
 * #authc.{@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#setUsernameParam(String) usernameParam} = username
 * #authc.{@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#setPasswordParam(String) passwordParam} = password
 * #authc.{@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#setRememberMeParam(String) rememberMeParam} = rememberMe
 * #authc.{@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#setSuccessUrl(String) successUrl}  = /login.jsp
 * #authc.{@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#setFailureKeyAttribute(String) failureKeyAttribute} = {@link org.jsecurity.web.filter.authc.FormAuthenticationFilter#DEFAULT_ERROR_KEY_ATTRIBUTE_NAME}
 * #
 * # Http BASIC Authentication filter:
 * #<a name="authcBasic"></a>authcBasic = {@link org.jsecurity.web.filter.authc.BasicHttpAuthenticationFilter}
 * #authcBasic.{@link org.jsecurity.web.filter.authc.BasicHttpAuthenticationFilter#setApplicationName(String) applicationName} = application
 * #
 * # Roles filter: requires the requesting user to have one or more roles for the request to continue.
 * # If they do not have the specified roles, they are redirected to the specified URL.
 * #<a name="roles"></a>roles = {@link org.jsecurity.web.filter.authz.RolesAuthorizationFilter}
 * #roles.{@link org.jsecurity.web.filter.authz.RolesAuthorizationFilter#setUnauthorizedUrl(String) url} =
 * # (note the above url is null by default, which will cause an HTTP 403 (Access Denied) response instead
 * # of redirecting to a page.  If you want to show a 'nice page' instead, you should specify that url.
 * #
 * # Permissions filter: requires the requesting user to have one or more permissions for the request to
 * # continue, and if they do not, redirects them to the specified URL.
 * #<a name="perms"></a>perms = {@link org.jsecurity.web.filter.authz.PermissionsAuthorizationFilter}
 * #perms.{@link org.jsecurity.web.filter.authz.PermissionsAuthorizationFilter#setUnauthorizedUrl(String) url} =
 * # (note the above url is null by default, which will cause an HTTP 403 (Access Denied) response instead
 * # of redirecting to a page.  If you want to show a 'nice page' instead, you should specify that url.  Many
 * # applications like to use the same url specified in roles.url above.
 * #
 * #
 * # Define your own filters here.  To properly handle url path matching (see the [urls] section below), your
 * # filter should extend the {@link org.jsecurity.web.filter.PathMatchingFilter PathMatchingFilter} abstract class.
 *
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
 * # discard the brackets - that is, filterN[] just becomes filterN.
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
 * # (Note that because elements within brackets [ ] are comma-delimited themselves, we needed to escape the permission
 * # actions of 'lan,wan' with quotes.  If we didn't do that, the permission filter would interpret
 * # the text between the brackets as two permissions: 'remote:invoke:lan' and 'wan' instead of the
 * # single desired 'remote:invoke:lan,wan' token.  So, you can use quotes wherever you need to escape internal
 * # commas.)
 *
 * /account/** = <a href="#authcBasic">authcBasic</a>
 * /remoting/** = <a href="#authcBasic">authcBasic</a>, <a href="#roles">roles</a>[b2bClient], <a href="#perms">perms</a>[remote:invoke:"lan,wan"]
 *
 * &lt;/param-value&gt;&lt;/init-param&gt;
 * &lt;/filter&gt;
 *
 *
 * &lt;filter-mapping&gt;
 * &lt;filter-name&gt;JSecurityFilter&lt;/filter-name&gt;
 * &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;</pre>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class JSecurityFilter extends OncePerRequestFilter {

    //TODO - complete JavaDoc

    public static final String SECURITY_MANAGER_CONTEXT_KEY = SecurityManager.class.getName() + "_SERVLET_CONTEXT_KEY";

    public static final String CONFIG_CLASS_NAME_INIT_PARAM_NAME = "configClassName";
    public static final String CONFIG_INIT_PARAM_NAME = "config";
    public static final String CONFIG_URL_INIT_PARAM_NAME = "configUrl";

    private static final Log log = LogFactory.getLog(JSecurityFilter.class);    

    protected String config;
    protected String configUrl;
    protected String configClassName;
    protected WebConfiguration configuration;

    // Reference to the security manager used by this filter
    protected SecurityManager securityManager;

    public JSecurityFilter() {
        this.configClassName = IniWebConfiguration.class.getName();
    }

    public WebConfiguration getConfiguration() {
        return configuration;
    }

    public void setConfiguration(WebConfiguration configuration) {
        this.configuration = configuration;
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected void setSecurityManager(SecurityManager sm) {
        this.securityManager = sm;
    }

    protected void onFilterConfigSet() throws Exception {
        applyInitParams();
        WebConfiguration config = configure();
        setConfiguration(config);

        // Retrieve and store a reference to the security manager
        SecurityManager sm = ensureSecurityManager(config);
        setSecurityManager(sm);
    }

    /**
     * Retrieves the security manager for the given configuration.
     *
     * @param config the configuration for this filter.
     * @return the security manager that this filter should use.
     */
    protected SecurityManager ensureSecurityManager(Configuration config) {
        SecurityManager sm = config.getSecurityManager();

        // If the config doesn't return a security manager, build one by default.
        if (sm == null) {
            if (log.isInfoEnabled()) {
                log.info("Configuration instance [" + config + "] did not provide a SecurityManager.  No config " +
                        "specified?  Defaulting to a " + DefaultWebSecurityManager.class.getName() + " instance...");
            }
            sm = new DefaultWebSecurityManager();
        }

        return sm;
    }

    protected void applyInitParams() {
        FilterConfig config = getFilterConfig();

        String configCN = clean(config.getInitParameter(CONFIG_CLASS_NAME_INIT_PARAM_NAME));
        if (configCN != null) {
            if (ClassUtils.isAvailable(configCN)) {
                this.configClassName = configCN;
            } else {
                String msg = "configClassName fully qualified class name value [" + configCN + "] is not " +
                        "available in the classpath.  Please ensure you have typed it correctly and the " +
                        "corresponding class or jar is in the classpath.";
                throw new ConfigurationException(msg);
            }
        }

        this.config = clean(config.getInitParameter(CONFIG_INIT_PARAM_NAME));
        this.configUrl = clean(config.getInitParameter(CONFIG_URL_INIT_PARAM_NAME));
    }

    protected WebConfiguration configure() {
        WebConfiguration conf = (WebConfiguration) ClassUtils.newInstance(this.configClassName);
        applyFilterConfig(conf);
        applyUrlConfig(conf);
        applyEmbeddedConfig(conf);
        LifecycleUtils.init(conf);
        return conf;
    }

    protected void applyFilterConfig(WebConfiguration conf) {
        if (log.isDebugEnabled()) {
            String msg = "Attempting to inject the FilterConfig (using 'setFilterConfig' method) into the " +
                    "instantiated WebConfiguration for any wrapped Filter initialization...";
            log.debug(msg);
        }
        try {
            PropertyDescriptor pd = PropertyUtils.getPropertyDescriptor(conf, "filterConfig");
            if (pd != null) {
                PropertyUtils.setProperty(conf, "filterConfig", getFilterConfig());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error setting FilterConfig on WebConfiguration instance.", e);
            }
        }
    }

    protected void applyEmbeddedConfig(WebConfiguration conf) {
        if (this.config != null) {
            try {
                PropertyDescriptor pd = PropertyUtils.getPropertyDescriptor(conf, "config");

                if (pd != null) {
                    PropertyUtils.setProperty(conf, "config", this.config);
                } else {
                    String msg = "The 'config' filter param was specified, but there is no " +
                            "'setConfig(String)' method on the Configuration instance [" + conf + "].  If you do " +
                            "not require the 'config' filter param, please comment it out, or if you do need it, " +
                            "please ensure your Configuration instance has a 'setConfig(String)' method to receive it.";
                    throw new ConfigurationException(msg);
                }
            } catch (Exception e) {
                String msg = "There was an error setting the 'config' property of the Configuration object.";
                throw new ConfigurationException(msg, e);
            }
        }
    }

    protected void applyUrlConfig(WebConfiguration conf) {
        if (this.configUrl != null) {
            try {
                PropertyDescriptor pd = PropertyUtils.getPropertyDescriptor(conf, "configUrl");

                if (pd != null) {
                    PropertyUtils.setProperty(conf, "configUrl", this.configUrl);
                } else {
                    String msg = "The 'configUrl' filter param was specified, but there is no " +
                            "'setConfigUrl(String)' method on the Configuration instance [" + conf + "].  If you do " +
                            "not require the 'configUrl' filter param, please comment it out, or if you do need it, " +
                            "please ensure your Configuration instance has a 'setConfigUrl(String)' method to receive it.";
                    throw new ConfigurationException(msg);
                }
            } catch (Exception e) {
                String msg = "There was an error setting the 'configUrl' property of the Configuration object.";
                throw new ConfigurationException(msg, e);
            }
        }
    }

    protected boolean isHttpSessions() {
        SecurityManager secMgr = getSecurityManager();
        if (secMgr instanceof DefaultWebSecurityManager) {
            return ((DefaultWebSecurityManager) secMgr).isHttpSessionMode();
        } else {
            return true;
        }
    }

    protected InetAddress getInetAddress(ServletRequest request) {
        return WebUtils.getInetAddress(request);
    }

    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse,
                                    FilterChain origChain) throws ServletException, IOException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        ThreadContext.bind(getInetAddress(request));

        boolean httpSessions = isHttpSessions();
        request = new JSecurityHttpServletRequest(request, getServletContext(), httpSessions);
        if (!httpSessions) {
            //the JSecurityHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using JSecurity sessions (i.e. not simple HttpSession based sessions):
            response = new JSecurityHttpServletResponse(response, getServletContext(), (JSecurityHttpServletRequest) request);
        }

        WebUtils.bind(request);
        WebUtils.bind(response);
        ThreadContext.bind(getSecurityManager());
        ThreadContext.bind(getSecurityManager().getSubject());

        FilterChain chain = getConfiguration().getChain(request, response, origChain);
        if (chain == null) {
            chain = origChain;
            if (log.isTraceEnabled()) {
                log.trace("No security filter chain configured for the current request.  Using default.");
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace(" Using configured filter chain for the current request.");
            }
        }

        try {
            chain.doFilter(request, response);
        } finally {
            ThreadContext.unbindSubject();
            ThreadContext.unbindSecurityManager();
            WebUtils.unbindServletResponse();
            WebUtils.unbindServletRequest();
            ThreadContext.unbindInetAddress();
        }
    }

    public void destroy() {
        LifecycleUtils.destroy(getConfiguration());
    }
}
