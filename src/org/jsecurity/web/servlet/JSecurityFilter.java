/*
 * Copyright 2005-2008 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.web.servlet;

import static org.jsecurity.util.StringUtils.*;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityWebSupport;
import org.jsecurity.web.interceptor.DefaultInterceptorBuilder;
import org.jsecurity.web.interceptor.InterceptorBuilder;
import org.jsecurity.web.interceptor.PathConfigWebInterceptor;
import org.jsecurity.web.interceptor.WebInterceptor;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

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
 * #       Everything else is just commented to explain things in-depth. Feel free to delete any
   #       comments that you don't want to read ;)
   #
   # All defaults are listed below but commented out.  If you want to change any value, you only
   # need to uncomment the line you want to change.

   [main]
   # The 'main' section defines JSecurity-wide configuration.
   #
   # Session Mode: By default, JSecurity's Session infrastructure in a web environment will use the
   # Servlet container's HttpSession.  However, if you need to share session state across client types
   # (e.g. Web MVC plus Java Web Start or Flash), or are doing distributed/shared Sessions for
   # Single Sign On, HttpSessions aren't good enough.  You'll need to use JSecurity's more powerful
   # (and client-agnostic) session management.  You can enable this by uncommenting the following line
   # and changing 'http' to 'jsecurity'
   #
   #sessionMode = http

   [interceptors]

   # This section defines a 'pool' of all the available interceptors that are available to the url path
   # definitions below in the [urls] section.
   #
   # The commented values are provided by JSecurity by default.  You can uncomment any line that you wish
   # to override.  It is not necessary to uncomment all of an interceptor's properties or even the main
   # name to class definition itself - you only need to uncomment the lines you want to override.
   #
   # Each interceptor is configured based on its functionality and/or protocol.  You should read each
   # interceptor's JavaDoc to fully understand what each does and how it works as well as how it would
   # affect the user experience.
   #
   # Http BASIC Authentication interceptor: requires the requesting user to be authenticated for the request
   # to continue, and if they're not, forces login via an Http BASIC browser dialog.  Upon successful login,
   # they're allowed to continue on to the requested resource/url.
   #authcBasic = org.jsecurity.web.interceptor.authc.BasicHttpAuthenticationWebInterceptor
   #authcBasic.applicationName = JSecurity Quickstart
   #
   # Roles interceptor: requires the requesting user to have one or more roles for the request to continue
   # and if they do not, redirects them to the 'unauthorizedPage' defined in the [global] section.
   #roles = org.jsecurity.web.interceptor.authz.RolesAuthorizationWebInterceptor
   #
   # Permissions interceptor: requires the requesting user to have one or more permissions for the request to
   # continue, and if they do not, redirects them to the 'unauthorizedPage' defined in the [global] section.
   #perms = org.jsecurity.web.interceptor.authz.PermissionsAuthorizationWebInterceptor
   #
   #
   #
   # Define your own interceptors here.  To properly handle path matching, all interceptor implementations
   # should extend the org.jsecurity.web.interceptor.PathMatchingWebInterceptor abstract class.

   [urls]

   # This section defines url path mappings.
   #
   # Each mapping entry must be on a single line and conform to the following format:
   #
   # ant_path_expression = path_specific_interceptor_chain_definition
   #
   # For each request that matches a specified path, the corresponding value defines a comma-delimited chain of
   # filters/interceptors to execute for that request.
   #
   # This is incredibly powerful in that you can define arbitrary filter chains for any given request pattern
   # to greatly customize the security experience.
   #
   # The path_specific_interceptor_chain_definition must match the following format:
   #
   # interceptor1[optional_config1], interceptor2[optional_config2], ..., interceptorN[optional_configN]
   #
   # where 'interceptorN' is the name of an interceptor defined above in the [interceptors] section and
   # optional_config is any (optional) string that has meaning for that particular interceptor for
   # _that particular path_.
   #
   # And because tokens define chains, order matters!  Define the interceptor tokens for each url path pattern
   # in the order you want them to filter.
   #
   # Finally, each interceptor is free to handle the response however it wants if its necessary
   # conditions are not met (redirect, HTTP error code, direct rendering, etc).  Otherwise, it is expected
   # that the request will continue on to its destination page.
   #
   # Examples:
   #
   # To illustrate chain configuration, look at the /account/** mapping below.  This says
   # "apply the above 'authc' interceptor to any request matching the '/account/**' pattern".  Since the
   # 'authc' interceptor does not need any path-specific config, it doesn't have any extra config brackets [].
   # (the 'authc' interceptor will force a login for unauthenticated users and then send them to the
   #  originally requested URL).
   #
   # The /remoting/** definition on the other hand uses the 'roles' and 'perms' interceptors which do use
   # bracket notation.  That definition says:
   #
   # "To access /remoting/** urls, ensure that the user is first authenticated ('authc'), then that user must
   # be verified to have the 'b2bClient' role, and then finally they must have the
   # 'remote:invoke:lan,wan' permission."
   #
   # (Note that because elements within brackets [ ] are comma-delimited, we needed to escape the permission
   # actions of 'lan,wan' with quotes.  If we didn't do that, the permission interceptor would interpret
   # the text between the brackets as two permissions: 'remote:invoke:lan' and 'wan' instead of the
   # single desired 'remote:invoke:lan,wan' token.  So, you can use quotes wherever you need to escape internal
   # commas.)

   /account/** = authcBasic
   /remoting/** = authcBasic, roles[b2bClient], perms[remote:invoke:"lan,wan"]

   &lt;/param-value&gt;&lt;/init-param&gt;
&lt;/filter&gt;


&lt;filter-mapping&gt;
    &lt;filter-name&gt;JSecurityFilter&lt;/filter-name&gt;
    &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
&lt;/filter-mapping&gt;</pre>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class JSecurityFilter extends SecurityManagerFilter {

    private static final String[] CONFIG_SECTIONS = {"[global]", "[interceptors]", "[urls]"};

    protected String config = null;
    protected String global = null;
    protected String interceptors = null;
    protected String urls = null;
    protected String unauthorizedPage;

    protected Map<String, Object> filtersAndInterceptors;

    protected InterceptorBuilder interceptorBuilder = new DefaultInterceptorBuilder();

    private List<Filter> filters;

    public Map<String, Object> getFiltersAndInterceptors() {
        return filtersAndInterceptors;
    }

    public void setFiltersAndInterceptors(Map<String, Object> filtersAndInterceptors) {
        this.filtersAndInterceptors = filtersAndInterceptors;
    }

    public String getConfig() {
        return config;
    }

    public void setConfig(String config) {
        this.config = config;
    }

    public String getGlobal() {
        return global;
    }

    public void setGlobal(String global) {
        this.global = global;
    }

    public String getInterceptors() {
        return interceptors;
    }

    public void setInterceptors(String interceptors) {
        this.interceptors = interceptors;
    }

    public String getUrls() {
        return urls;
    }

    public void setUrls(String urls) {
        this.urls = urls;
    }

    public String getUnauthorizedPage() {
        return unauthorizedPage;
    }

    public void setUnauthorizedPage(String unauthorizedPage) {
        this.unauthorizedPage = unauthorizedPage;
    }

    protected void afterSecurityManagerSet() throws Exception {
        applyInitParams();
        applyConfig();
        ensureWebInterceptors();
        applyUrlMappings();
        applyWebInterceptorFilters();
    }

    protected void applyConfig() throws Exception {

        String config = getConfig();
        //The following 3 values will be non-null if they have been overidden.
        //If they are overridden, we don't set them in the scanning below so that we
        //retain user-configured values.
        String global = getGlobal();
        String interceptors = getInterceptors();
        String urls = getUrls();

        if (config != null) {

            boolean inGlobal = false;
            boolean inInterceptors = false;

            StringBuffer section = new StringBuffer();
            Scanner scanner = new Scanner(config);
            while (scanner.hasNextLine()) {

                String line = clean(scanner.nextLine());
                //ignore comments:
                if ( line != null && line.startsWith( "#" ) ) {
                    line = null;
                }
                
                if (line != null) {
                    if (CONFIG_SECTIONS[0].equals(line.toLowerCase())) {
                        inGlobal = true;
                        if ( log.isDebugEnabled() ) {
                            log.debug( "Parsing " + CONFIG_SECTIONS[0] );
                        }
                    } else if (CONFIG_SECTIONS[1].equals(line.toLowerCase())) {
                        if (inGlobal) {
                            if (global == null && section.length() > 0) { //only set if not set previously by the user
                                global = section.toString();
                                setGlobal(global);
                            }
                        }
                        section = new StringBuffer();
                        inGlobal = false;
                        inInterceptors = true;
                        if ( log.isDebugEnabled() ) {
                            log.debug( "Parsing " + CONFIG_SECTIONS[1] );
                        }
                    } else if (CONFIG_SECTIONS[2].equals(line.toLowerCase())) {
                        if (inInterceptors) {
                            if (interceptors == null && section.length() > 0) { //only set if not set previously by the user
                                interceptors = section.toString();
                                setInterceptors(interceptors);
                            }
                        }
                        section = new StringBuffer();
                        inInterceptors = false;
                        inGlobal = false;
                        if ( log.isDebugEnabled() ) {
                            log.debug( "Parsing " + CONFIG_SECTIONS[2] );
                        }
                    } else {
                        section.append(line).append("\n");
                    }
                }
            }

            if (urls == null && section.length() > 0) {
                urls = section.toString();
                setUrls(urls);
            }
        }
    }

    protected void applyInitParams() {
        FilterConfig config = getFilterConfig();

        //only apply init params for the properties that are null - this allows subclasses to set the values
        //before the init params are read, which essentially allows overrides.
        if (getConfig() == null) {
            setConfig( clean(config.getInitParameter("config") ) );
        }
    }

    protected void ensureWebInterceptors() {
        Map<String, Object> interceptors = this.interceptorBuilder.buildInterceptors(getInterceptors());

        if (this.filtersAndInterceptors != null && !this.filtersAndInterceptors.isEmpty()) {
            interceptors.putAll(this.filtersAndInterceptors);
        }

        if (!interceptors.isEmpty()) {
            setFiltersAndInterceptors(interceptors);
        }
    }

    protected void applyWebInterceptorFilters() throws ServletException {

        Map<String, Object> interceptors = getFiltersAndInterceptors();

        if (log.isDebugEnabled()) {
            log.debug("Interceptors configured: " + interceptors.size());
        }

        if (interceptors != null && !interceptors.isEmpty()) {

            List<Filter> filters = new ArrayList<Filter>(interceptors.size());

            for (String key : interceptors.keySet()) {

                Object value = interceptors.get(key);

                Filter filter = null;

                if ( value instanceof Filter ) {
                    filter = (Filter)value;
                } else if ( value instanceof WebInterceptor ) {
                    WebInterceptor interceptor = (WebInterceptor) value;
                    WebInterceptorFilter wiFilter = new WebInterceptorFilter();
                    wiFilter.setWebInterceptor(interceptor);
                    filter = wiFilter;
                } else if ( value != null ) {
                    String msg = "filtersAndInterceptors collection contains an object of type [" +
                            value.getClass().getName() + "].  This instance does not implement " +
                            Filter.class.getName() + " or the " + WebInterceptor.class.getName() + " interfaces.  " +
                            "Only filters and interceptors should be configured.";
                    throw new ServletException(msg);

                }

                if (filter != null) {
                    filter.init(getFilterConfig());
                    filters.add(filter);
                }
            }

            this.filters = filters;
        }

        if (log.isDebugEnabled()) {
            log.debug("Filters configured and/or wrapped: " + (filters != null ? filters.size() : 0));
        }
    }

    protected void applyUrlMappings() throws ParseException {

        if (this.urls == null || this.filtersAndInterceptors == null || this.filtersAndInterceptors.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No urls or filters/interceptors to process.");
            }
            return;
        }

        if (log.isTraceEnabled()) {
            log.trace("Before url scanning.");
        }

        Scanner scanner = new Scanner(this.urls);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            String[] pathValue = splitKeyValue(line);
            String path = pathValue[0];
            String value = pathValue[1];

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
                Object interceptor = this.filtersAndInterceptors.get(name);
                if (interceptor instanceof PathConfigWebInterceptor) {
                    if (log.isDebugEnabled()) {
                        log.debug("Applying path [" + path + "] to interceptor [" + name + "] " +
                                "with config [" + config + "]");
                    }
                    ((PathConfigWebInterceptor) interceptor).processPathConfig(path, config);
                }
            }
        }
    }

    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse,
                                    FilterChain origChain) throws ServletException, IOException {
        FilterChain chain = origChain;
        if (this.filters != null && !this.filters.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("Filters and/or WebInterceptors configured - wrapping FilterChain.");
            }
            chain = new FilterChainWrapper(chain, this.filters);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("No Filters or WebInterceptors configured - FilterChain will not be wrapped.");
            }
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        ThreadContext.bind(SecurityWebSupport.getInetAddress(request));

        boolean httpSessions = isHttpSessions();
        request = new JSecurityHttpServletRequest(request, getServletContext(), httpSessions);
        if (!httpSessions) {
            //the JSecurityHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using JSecurity sessions (i.e. not simple HttpSession based sessions):
            response = new JSecurityHttpServletResponse(response, getServletContext(), (JSecurityHttpServletRequest) request);
        }

        ThreadContext.bind(request);
        ThreadContext.bind(response);
        ThreadContext.bind(getSecurityManager().getSubject());

        try {
            chain.doFilter(request, response);
        } finally {
            ThreadContext.unbindServletRequest();
            ThreadContext.unbindServletResponse();
            ThreadContext.unbindInetAddress();
            ThreadContext.unbindSubject();
        }
    }

    public void destroy() {
        if (this.filters != null && !this.filters.isEmpty()) {
            for (Filter filter : filters) {
                try {
                    filter.destroy();
                } catch (Exception e) {
                    if (log.isWarnEnabled()) {
                        log.warn("Unable to cleanly destroy filter [" + filter + "].  Ignoring (shutting down)...", e);
                    }
                }
            }
        }

        super.destroy();
    }
}
