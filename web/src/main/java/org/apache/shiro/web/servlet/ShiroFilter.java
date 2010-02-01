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

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.Configuration;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;
import org.apache.shiro.web.DefaultWebSecurityManager;
import org.apache.shiro.web.WebSecurityManager;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.config.IniWebConfiguration;
import org.apache.shiro.web.config.WebConfiguration;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.support.WebSubjectThreadState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.PropertyDescriptor;
import java.io.IOException;

/**
 * Main ServletFilter that configures and enables all Shiro functions within a web application.
 * <p/>
 * The following is a fully commented example that documents how to configure it:
 * <pre>&lt;filter&gt;
 * &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 * &lt;filter-class&gt;org.apache.shiro.web.servlet.ShiroFilter&lt;/filter-class&gt;
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
 * # The configuration is essentially an object graph definition in a .properties style format.  The beans defined
 * # would be those that are used to construct the application's SecurityManager.  It is essentially 'poor man's'
 * # dependency injection via a .properties format.
 * #
 * # --- Defining Realms ---
 * #
 * # Any Realm defined here will automatically be injected into Shiro's default SecurityManager created at start up.
 * # For example:
 * #
 * # myRealm = example.pkg.security.MyRealm
 * #
 * # This would instantiate the some.pkg.security.MyRealm class with a default no-arg constructor and inject it into
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
 * # If the .properties style isn't robust enough for your needs, you also have the option of implementing the
 * # {@link org.apache.shiro.realm.RealmFactory org.apache.shiro.realm.RealmFactory} interface with more complex construction
 * # logic.  Then you can declare the implementation here instead.  The realms it returns will be injected in to the
 * # SecurityManager just as the individual Realms are.  For example:
 * #
 * # aRealmFactory = some.pkg.ClassThatImplementsRealmFactory
 * #
 * # --- SessionManager properties ---
 * #
 * # Except for Realms and RealmFactories, all other objects should be defined and set on the SecurityManager directly.
 * # The default 'securityManager' bean is an instance of {@link org.apache.shiro.web.DefaultWebSecurityManager}, so you
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
 * #securityManager.{@link org.apache.shiro.web.DefaultWebSecurityManager#setSessionMode(String) sessionMode} = http
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
 * #
 * /account/** = <a href="#authcBasic">authcBasic</a>
 * /remoting/** = <a href="#authcBasic">authcBasic</a>, <a href="#roles">roles</a>[b2bClient], <a href="#perms">perms</a>[remote:invoke:"lan,wan"]
 * #
 * &lt;/param-value&gt;&lt;/init-param&gt;
 * &lt;/filter&gt;
 * #
 * #
 * &lt;filter-mapping&gt;
 * &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 * &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;</pre>
 * <p/>
 * <p/>
 * <b>Do not use this! It will be removed prior to 1.0 final!</b>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @see IniShiroFilter
 * @since 0.1
 * @deprecated use {@link org.apache.shiro.web.servlet.IniShiroFilter} instead.
 *             <b>Will be removed prior to 1.0 final!</b>
 */
@Deprecated
public class ShiroFilter extends OncePerRequestFilter {

    //TODO - complete JavaDoc

    public static final String CONFIG_CLASS_NAME_INIT_PARAM_NAME = "configClassName";
    public static final String CONFIG_INIT_PARAM_NAME = "config";
    public static final String CONFIG_URL_INIT_PARAM_NAME = "configUrl";

    @SuppressWarnings({"deprecation"})
    private static final Logger log = LoggerFactory.getLogger(ShiroFilter.class);

    protected String config;
    protected String configUrl;
    protected String configClassName;
    protected WebConfiguration configuration;

    // Reference to the security manager used by this filter
    protected WebSecurityManager securityManager;

    // Used to determine which chain should handle an incoming request/response
    private FilterChainResolver filterChainResolver;

    public ShiroFilter() {
        this.configClassName = IniWebConfiguration.class.getName();
    }

    public WebConfiguration getConfiguration() {
        return configuration;
    }

    public void setConfiguration(WebConfiguration configuration) {
        this.configuration = configuration;
    }

    public WebSecurityManager getSecurityManager() {
        return securityManager;
    }

    protected void setSecurityManager(WebSecurityManager sm) {
        this.securityManager = sm;
    }

    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    public void setFilterChainResolver(FilterChainResolver filterChainResolver) {
        this.filterChainResolver = filterChainResolver;
    }

    protected void onFilterConfigSet() throws Exception {
        applyInitParams();
        WebConfiguration config = configure();
        setConfiguration(config);
        ensureSecurityManager(config);
        applyFilterChainResolver(config);
    }

    /**
     * Ensures a SecurityManager exists, and if not, creates one automatically and ensures it is available for
     * use during requests.
     *
     * @param config the configuration for this filter.
     */
    protected void ensureSecurityManager(Configuration config) {
        WebSecurityManager securityManager = getSecurityManager();
        boolean existing = securityManager != null;
        if (!existing && config != null) {
            // Get the configured security manager. If it isn't an implementation of
            // WebSecurityManager, then we raise an error.
            SecurityManager sm = config.getSecurityManager();
            if (!(sm instanceof WebSecurityManager)) {
                String msg = "The configured security manager is not an instance of WebSecurityManager, so " +
                        "it can not be used with the Shiro servlet filter.";
                throw new ConfigurationException(msg);
            }
            securityManager = (WebSecurityManager) sm;
        }

        // If the config doesn't return a security manager, build one by default.
        if (securityManager == null) {
            if (log.isInfoEnabled()) {
                log.info("Configuration instance [" + config + "] did not provide a SecurityManager.  No config " +
                        "specified?  Defaulting to a " + DefaultWebSecurityManager.class.getName() + " instance...");
            }
            securityManager = new DefaultWebSecurityManager();
        }

        if (!existing) {
            setSecurityManager(securityManager);
        }
    }

    protected void applyFilterChainResolver(WebConfiguration config) {
        FilterChainResolver resolver = getFilterChainResolver();
        if (resolver == null && config != null) {
            resolver = config.getFilterChainResolver();
            if (resolver != null) {
                setFilterChainResolver(resolver);
            }
        }
    }

    protected void applyInitParams() {

        String configCN = getInitParam(CONFIG_CLASS_NAME_INIT_PARAM_NAME);
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

        this.config = getInitParam(CONFIG_INIT_PARAM_NAME);
        this.configUrl = getInitParam(CONFIG_URL_INIT_PARAM_NAME);
    }

    protected WebConfiguration configure() {
        WebConfiguration webConfiguration = (WebConfiguration) ClassUtils.newInstance(this.configClassName);
        applyFilterConfig(webConfiguration);
        applyUrlConfig(webConfiguration);
        applyEmbeddedConfig(webConfiguration);
        LifecycleUtils.init(webConfiguration);
        return webConfiguration;
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
                            "please ensure your Configuration class has a 'setConfig(String)' method to receive it.";
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
                            "please ensure your Configuration class has a 'setConfigUrl(String)' method to receive it.";
                    throw new ConfigurationException(msg);
                }
            } catch (Exception e) {
                String msg = "There was an error setting the 'configUrl' property of the Configuration object.";
                throw new ConfigurationException(msg, e);
            }
        }
    }

    protected boolean isHttpSessions() {
        return getSecurityManager().isHttpSessionMode();
    }

    /**
     * Wraps the original HttpServletRequest in a {@link ShiroHttpServletRequest}, which is required for supporting
     * Servlet Specification behavior backed by a {@link org.apache.shiro.subject.Subject Subject} instance.
     *
     * @param orig the original Servlet Container-provided incoming {@code HttpServletRequest} instance.
     * @return {@link ShiroHttpServletRequest ShiroHttpServletRequest} instance wrapping the original.
     * @since 1.0
     */
    protected ServletRequest wrapServletRequest(HttpServletRequest orig) {
        return new ShiroHttpServletRequest(orig, getServletContext(), isHttpSessions());
    }

    /**
     * Prepares the {@code ServletRequest} instance that will be passed to the {@code FilterChain} for request
     * processing.
     * <p/>
     * If the {@code ServletRequest} is an instance of {@link HttpServletRequest}, the value returned from this method
     * is obtained by calling {@link #wrapServletRequest(javax.servlet.http.HttpServletRequest)} to allow Shiro-specific
     * HTTP behavior, otherwise the original {@code ServletRequest} argument is returned.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the Servlet Container provided {@code FilterChain} that will receive the returned request.
     * @return the {@code ServletRequest} instance that will be passed to the {@code FilterChain} for request processing.
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected ServletRequest prepareServletRequest(ServletRequest request, ServletResponse response, FilterChain chain) {
        ServletRequest toUse = request;
        if (request instanceof HttpServletRequest) {
            HttpServletRequest http = (HttpServletRequest) request;
            toUse = wrapServletRequest(http);
        }
        return toUse;
    }

    /**
     * Returns a new {@link ShiroHttpServletResponse} instance, wrapping the {@code orig} argument, in order to provide
     * correct URL rewriting behavior required by the Servlet Specification when using Shiro-based sessions (and not
     * Servlet Container HTTP-based sessions).
     *
     * @param orig    the original {@code HttpServletResponse} instance provided by the Servlet Container.
     * @param request the {@code ShiroHttpServletRequest} instance wrapping the original request.
     * @return the wrapped ServletResponse instance to use during {@link FilterChain} execution.
     * @since 1.0
     */
    protected ServletResponse wrapServletResponse(HttpServletResponse orig, ShiroHttpServletRequest request) {
        return new ShiroHttpServletResponse(orig, getServletContext(), request);
    }

    /**
     * Prepares the {@code ServletResponse} instance that will be passed to the {@code FilterChain} for request
     * processing.
     * <p/>
     * This implementation delegates to {@link #wrapServletRequest(javax.servlet.http.HttpServletRequest)}
     * only if Shiro-based sessions are enabled (that is, !{@link #isHttpSessions()}) and the request instance is a
     * {@link ShiroHttpServletRequest}.  This ensures that any URL rewriting that occurs is handled correctly using the
     * Shiro-managed Session's sessionId and not a servlet container session ID.
     * <p/>
     * If HTTP-based sessions are enabled (the default), then this method does nothing and just returns the
     * {@code ServletResponse} argument as-is, relying on the default Servlet Container URL rewriting logic.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @param chain    the Servlet Container provided {@code FilterChain} that will receive the returned request.
     * @return the {@code ServletResponse} instance that will be passed to the {@code FilterChain} during request processing.
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected ServletResponse prepareServletResponse(ServletRequest request, ServletResponse response, FilterChain chain) {
        ServletResponse toUse = response;
        if (!isHttpSessions() && (request instanceof ShiroHttpServletRequest) &&
                (response instanceof HttpServletResponse)) {
            //the ShiroHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using Shiro sessions (i.e. not simple HttpSession based sessions):
            toUse = wrapServletResponse((HttpServletResponse) response, (ShiroHttpServletRequest) request);
        }
        return toUse;
    }

    /**
     * Binds the current request/response pair and additional information to a thread-local to be made available to Shiro
     * during the course of the request/response process.  This implementation binds the request/response pair and
     * any associated Subject (and its relevant thread-based data) via a {@link org.apache.shiro.web.subject.support.WebSubjectThreadState}.  That
     * threadState is returned so it can be used during thread cleanup at the end of the request.
     * <p/>
     * To guarantee properly cleaned threads in a thread-pooled Servlet Container environment, the corresponding
     * {@link #unbind} method must be called in a {@code finally} block to ensure that the thread remains clean even
     * in the event of an exception thrown while processing the request.  This class's
     * {@link #doFilterInternal(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)}
     * method implementation does indeed function this way.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return ThreadStateManager the thread state used to bind necessary state for the request execution.
     * @since 1.0
     */
    protected ThreadState bind(ServletRequest request, ServletResponse response) {
        ThreadContext.bind(getSecurityManager());
        //currently the WebRememberMeManager needs the request/response bound in order to create the subject instance:
        WebUtils.bind(request);
        WebUtils.bind(response);

        WebSubject subject = new WebSubject.Builder().buildWebSubject();
        ThreadState threadState = new WebSubjectThreadState(subject);
        threadState.bind();
        return threadState;
    }

    /**
     * Unbinds (removes out of scope) the current {@code ServletRequest} and {@link ServletResponse}.
     * <p/>
     * This method implementation merely clears <em>all</em> thread state by calling
     * {@link org.apache.shiro.subject.support.SubjectThreadState#clear()} to guarantee
     * that <em>everything</em> that might have been bound to the thread by Shiro has been removed to ensure the
     * underlying Thread may be safely re-used in a thread-pooled Servlet Container environment.
     *
     * @param threadState the web thread state created when the request and response first were initiated.
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected void unbind(ThreadState threadState) {
        threadState.clear();
    }

    /**
     * Updates any 'native'  Session's last access time that might exist to the timestamp when this method is called.
     * If native sessions are not enabled (that is, standard Servlet container sessions are being used) or there is no
     * session ({@code subject.getSession(false) == null}), this method does nothing.
     * <p/>This method implementation merely calls
     * <code>Session.{@link org.apache.shiro.session.Session#touch() touch}()</code> on the session.
     *
     * @param request  incoming request - ignored, but available to subclasses that might wish to override this method
     * @param response outgoing response - ignored, but available to subclasses that might wish to override this method
     * @since 1.0
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected void updateSessionLastAccessTime(ServletRequest request, ServletResponse response) {
        if (!isHttpSessions()) { //'native' sessions
            Subject subject = SecurityUtils.getSubject();
            //Subject should never _ever_ be null, but just in case:
            if (subject != null) {
                Session session = subject.getSession(false);
                if (session != null) {
                    try {
                        session.touch();
                    } catch (Throwable t) {
                        log.error("session.touch() method invocation has failed.  Unable to update" +
                                "the corresponding session's last access time based on the incoming request.", t);
                    }
                }
            }
        }
    }

    /**
     * {@code doFilterInternal} implementation that sets-up, executes, and cleans-up a Shiro-filtered request.  It
     * performs the following ordered operations:
     * <ol>
     * <li>{@link #prepareServletRequest(ServletRequest, ServletResponse, FilterChain) Prepares}
     * the incoming {@code ServletRequest} for use during Shiro's processing</li>
     * <li>{@link #prepareServletResponse(ServletRequest, ServletResponse, FilterChain) Prepares}
     * the outgoing {@code ServletResponse} for use during Shiro's processing</li>
     * <li>{@link #bind(ServletRequest,ServletResponse) Binds} the request/response pair
     * and associated data to the currently executing thread for use during processing</li>
     * <li>{@link #updateSessionLastAccessTime(javax.servlet.ServletRequest, javax.servlet.ServletResponse) Updates}
     * any associated session's {@link org.apache.shiro.session.Session#getLastAccessTime() lastAccessTime} to ensure
     * session timeouts are honored</li>
     * <li>{@link #executeChain(ServletRequest,ServletResponse,FilterChain) Executes}
     * the appropriate {@code FilterChain}</li>
     * <li>{@link #unbind(org.apache.shiro.util.ThreadState) Unbinds} the request/response
     * pair and any other associated data from the thread.
     * </ul>
     * <p/>
     * The {@link #unbind(org.apache.shiro.util.ThreadState) unbind} method is called in a
     * {@code finally} block to guarantee the thread may be cleanly re-used in a thread-pooled Servlet Container
     * environment.
     *
     * @param servletRequest  the incoming {@code ServletRequest}
     * @param servletResponse the outgoing {@code ServletResponse}
     * @param chain           the container-provided {@code FilterChain} to execute
     * @throws ServletException if an error occurs
     * @throws IOException      if an IO error occurs
     */
    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws ServletException, IOException {

        ServletRequest request = prepareServletRequest(servletRequest, servletResponse, chain);
        ServletResponse response = prepareServletResponse(request, servletResponse, chain);

        ThreadState threadState = bind(request, response);

        try {
            updateSessionLastAccessTime(request, response);
            executeChain(request, response, chain);
        } finally {
            unbind(threadState);
        }
    }

    /**
     * Returns the {@code FilterChain} to execute for the given request.
     * <p/>
     * The {@code origChain} argument is the
     * original {@code FilterChain} supplied by the Servlet Container, but it may be modified to provide
     * more behavior by pre-pending further chains according to the Shiro configuration.
     * <p/>
     * This implementation returns the chain that will actually be executed by acquiring the chain from a
     * {@link #getFilterChainResolver() filterChainResolver}.  The resolver determines exactly which chain to
     * execute, typically based on URL configuration.  If no chain is returned from the resolver call
     * (returns {@code null}), then the {@code origChain} will be returned by default.
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the original {@code FilterChain} provided by the Servlet Container
     * @return the {@link FilterChain} to execute for the given request
     * @since 1.0
     */
    protected FilterChain getExecutionChain(ServletRequest request, ServletResponse response, FilterChain origChain) {
        FilterChain chain = origChain;
        FilterChain resolved = null;
        FilterChainResolver resolver = getFilterChainResolver();
        if (resolver != null) {
            resolved = resolver.getChain(request, response, origChain);
        } else {
            log.trace("No FilterChainResolver configured.  Attempting (deprecated) WebConfiguration resolution.");
            WebConfiguration config = getConfiguration();
            if (config != null) {
                //noinspection deprecation
                resolved = config.getChain(request, response, origChain);
            }
        }
        if (resolved != null) {
            log.trace("Resolved a configured FilterChain for the current request.");
            chain = resolved;
        } else {
            log.trace("No FilterChain configured for the current request.  Using the default.");
        }

        return chain;
    }

    /**
     * Executes a {@link FilterChain} for the given request.
     * <p/>
     * This implementation first delegates to
     * <code>{@link #getExecutionChain(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain) getExecutionChain}</code>
     * to allow the application's Shiro configuration to determine exactly how the chain should execute.  The resulting
     * value from that call is then executed directly by calling the returned {@code FilterChain}'s
     * {@link FilterChain#doFilter doFilter} method.  That is:
     * <pre>
     * FilterChain chain = {@link #getExecutionChain}(request, response, origChain);
     * chain.{@link FilterChain#doFilter doFilter}(request,response);</pre>
     *
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the Servlet Container-provided chain that may be wrapped further by an application-configured
     *                  chain of Filters.
     * @throws IOException      if the underlying {@code chain.doFilter} call results in an IOException
     * @throws ServletException if the underlying {@code chain.doFilter} call results in a ServletException
     * @since 1.0
     */
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
            throws IOException, ServletException {
        FilterChain chain = getExecutionChain(request, response, origChain);
        chain.doFilter(request, response);
    }

    /**
     * Destroys this Filter by destroying the {@link #getConfiguration() configuration} object.
     */
    public void destroy() {
        LifecycleUtils.destroy(getConfiguration());
    }
}
