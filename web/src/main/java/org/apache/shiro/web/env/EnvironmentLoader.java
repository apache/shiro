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
import org.apache.shiro.config.ResourceConfigurable;
import org.apache.shiro.util.ClassUtils;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.util.UnknownClassException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;

/**
 * An {@code EnvironmentLoader} is responsible for loading a web application's Shiro {@link WebEnvironment}
 * (which includes the web app's {@link org.apache.shiro.web.mgt.WebSecurityManager WebSecurityManager}) into the
 * {@code ServletContext} at application startup.
 * <p/>
 * In Shiro 1.1 and earlier, the Shiro ServletFilter was responsible for creating the {@code WebSecurityManager} and
 * any additional objects (security filters, etc).  However, any component not filtered by the Shiro Filter (such
 * as other context listeners) was not able to easily acquire the these objects to perform security operations.
 * <p/>
 * Due to this, in Shiro 1.2 and later, this {@code EnvironmentLoader} (or more likely, the
 * {@link EnvironmentLoaderListener} subclass) is the preferred mechanism to initialize
 * a Shiro environment.  The Shiro Filter, while still required for request filtering, will not perform this
 * initialization at startup if the {@code EnvironmentLoader} (or listener) runs first.
 * <h2>Usage</h2>
 * This implementation will look for two servlet context {@code context-param}s in {@code web.xml}:
 * {@code shiroEnvironmentClass} and {@code shiroConfigLocations} that customize how the {@code WebEnvironment} instance
 * will be initialized.
 * <h3>shiroEnvironmentClass</h3>
 * The {@code shiroEnvironmentClass} {@code context-param}, if it exists, allows you to specify the
 * fully-qualified implementation class name of the {@link WebEnvironment} to instantiate.  For example:
 * <pre>
 * &lt;context-param&gt;
 *     &lt;param-name&gt;shiroEnvironmentClass&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.bar.shiro.MyWebEnvironment&lt;/param-value&gt;
 * &lt;/context-param&gt;
 * </pre>
 * If not specified, the default value is the {@link IniWebEnvironment} class, which assumes Shiro's default
 * <a href="http://shiro.apache.org/configuration.html">INI configuration format</a>
 * <h3>shiroConfigLocations</h3>
 * The {@code shiroConfigLocations} {@code context-param}, if it exists, allows you to specify the config location(s)
 * (resource path(s)) that will be relayed to the instantiated {@link WebEnvironment}.  For example:
 * <pre>
 * &lt;context-param&gt;
 *     &lt;param-name&gt;shiroConfigLocations&lt;/param-name&gt;
 *     &lt;param-value&gt;/WEB-INF/someLocation/shiro.ini&lt;/param-value&gt;
 * &lt;/context-param&gt;
 * </pre>
 * The {@code WebEnvironment} implementation must implement the {@link ResourceConfigurable} interface if it is to
 * acquire the {@code shiroConfigLocations} value.
 * <p/>
 * If this {@code context-param} is not specified, the {@code WebEnvironment} instance determines default resource
 * lookup behavior.  For example, the {@link IniWebEnvironment} will check the following two locations for INI config
 * by default (in order):
 * <ol>
 * <li>/WEB-INF/shiro.ini</li>
 * <li>classpath:shiro.ini</li>
 * </ol>
 * <h2>Web Security Enforcement</h2>
 * Using this loader will only initialize Shiro's environment in a web application - it will not filter web requests or
 * perform web-specific security operations.  To do this, you must ensure that you have also configured the
 * {@link org.apache.shiro.web.servlet.ShiroFilter ShiroFilter} in {@code web.xml}.
 * <p/>
 * Finally, it should be noted that this implementation was based on ideas in Spring 3's
 * {@code org.springframework.web.context.ContextLoader} implementation - no need to reinvent the wheel for this common
 * behavior.
 *
 * @see EnvironmentLoaderListener
 * @see org.apache.shiro.web.servlet.ShiroFilter ShiroFilter
 * @since 1.2
 */
public class EnvironmentLoader {

    /**
     * Servlet Context config param for specifying the {@link WebEnvironment} implementation class to use:
     * {@code shiroEnvironmentClass}
     */
    public static final String ENVIRONMENT_CLASS_PARAM = "shiroEnvironmentClass";

    /**
     * Servlet Context config param for the resource path to use for configuring the {@link WebEnvironment} instance:
     * {@code shiroConfigLocations}
     */
    public static final String CONFIG_LOCATIONS_PARAM = "shiroConfigLocations";

    public static final String ENVIRONMENT_ATTRIBUTE_KEY = EnvironmentLoader.class.getName() + ".ENVIRONMENT_ATTRIBUTE_KEY";

    private static final Logger log = LoggerFactory.getLogger(EnvironmentLoader.class);

    /**
     * Initializes Shiro's {@link WebEnvironment} instance for the specified {@code ServletContext} based on the
     * {@link #CONFIG_LOCATIONS_PARAM} value.
     *
     * @param servletContext current servlet context
     * @return the new Shiro {@code WebEnvironment} instance.
     * @throws IllegalStateException if an existing WebEnvironment has already been initialized and associated with
     *                               the specified {@code ServletContext}.
     */
    public WebEnvironment initEnvironment(ServletContext servletContext) throws IllegalStateException {

        if (servletContext.getAttribute(ENVIRONMENT_ATTRIBUTE_KEY) != null) {
            String msg = "There is already a Shiro environment associated with the current ServletContext.  " +
                    "Check if you have multiple EnvironmentLoader* definitions in your web.xml!";
            throw new IllegalStateException(msg);
        }

        servletContext.log("Initializing Shiro environment");
        log.info("Starting Shiro environment initialization.");

        long startTime = System.currentTimeMillis();

        try {
            WebEnvironment environment = createEnvironment(servletContext);
            servletContext.setAttribute(ENVIRONMENT_ATTRIBUTE_KEY, environment);

            log.debug("Published WebEnvironment as ServletContext attribute with name [{}]",
                    ENVIRONMENT_ATTRIBUTE_KEY);

            if (log.isInfoEnabled()) {
                long elapsed = System.currentTimeMillis() - startTime;
                log.info("Shiro environment initialized in {} ms.", elapsed);
            }

            return environment;
        } catch (RuntimeException ex) {
            log.error("Shiro environment initialization failed", ex);
            servletContext.setAttribute(ENVIRONMENT_ATTRIBUTE_KEY, ex);
            throw ex;
        } catch (Error err) {
            log.error("Shiro environment initialization failed", err);
            servletContext.setAttribute(ENVIRONMENT_ATTRIBUTE_KEY, err);
            throw err;
        }
    }

    /**
     * Return the WebEnvironment implementation class to use, either the default
     * {@link IniWebEnvironment} or a custom class if specified.
     *
     * @param servletContext current servlet context
     * @return the WebEnvironment implementation class to use
     * @see #ENVIRONMENT_CLASS_PARAM
     * @see IniWebEnvironment
     */
    protected Class<?> determineWebEnvironmentClass(ServletContext servletContext) {
        String className = servletContext.getInitParameter(ENVIRONMENT_CLASS_PARAM);
        if (className != null) {
            try {
                return ClassUtils.forName(className);
            } catch (UnknownClassException ex) {
                throw new ConfigurationException(
                        "Failed to load custom WebEnvironment class [" + className + "]", ex);
            }
        } else {
            return IniWebEnvironment.class;
        }
    }

    /**
     * Instantiates a {@link WebEnvironment} based on the specified ServletContext.
     * <p/>
     * This implementation {@link #determineWebEnvironmentClass(javax.servlet.ServletContext) determines} a
     * {@link WebEnvironment} implementation class to use.  That class is instantiated, configured, and returned.
     * <p/>
     * This allows custom {@code WebEnvironment} implementations to be specified via a ServletContext init-param if
     * desired.  If not specified, the default {@link IniWebEnvironment} implementation will be used.
     *
     * @param sc current servlet context
     * @return the constructed Shiro WebEnvironment instance
     * @see MutableWebEnvironment
     * @see ResourceConfigurable
     */
    protected WebEnvironment createEnvironment(ServletContext sc) {

        Class<?> clazz = determineWebEnvironmentClass(sc);
        if (!MutableWebEnvironment.class.isAssignableFrom(clazz)) {
            throw new ConfigurationException("Custom WebEnvironment class [" + clazz.getName() +
                    "] is not of required type [" + WebEnvironment.class.getName() + "]");
        }

        String configLocations = sc.getInitParameter(CONFIG_LOCATIONS_PARAM);
        boolean configSpecified = StringUtils.hasText(configLocations);

        if (configSpecified && !(ResourceConfigurable.class.isAssignableFrom(clazz))) {
            String msg = "WebEnvironment class [" + clazz.getName() + "] does not implement the " +
                    ResourceConfigurable.class.getName() + "interface.  This is required to accept any " +
                    "configured " + CONFIG_LOCATIONS_PARAM + "value(s).";
            throw new ConfigurationException(msg);
        }

        MutableWebEnvironment environment = (MutableWebEnvironment) ClassUtils.newInstance(clazz);

        environment.setServletContext(sc);

        if (configSpecified && (environment instanceof ResourceConfigurable)) {
            ((ResourceConfigurable) environment).setConfigLocations(configLocations);
        }

        customizeEnvironment(environment);

        LifecycleUtils.init(environment);

        return environment;
    }

    protected void customizeEnvironment(WebEnvironment environment) {
    }

    /**
     * Destroys the {@link WebEnvironment} for the given servlet context.
     *
     * @param servletContext the ServletContext attributed to the WebSecurityManager
     */
    public void destroyEnvironment(ServletContext servletContext) {
        servletContext.log("Cleaning up Shiro Environment");
        try {
            Object environment = servletContext.getAttribute(ENVIRONMENT_ATTRIBUTE_KEY);
            LifecycleUtils.destroy(environment);
        } finally {
            servletContext.removeAttribute(ENVIRONMENT_ATTRIBUTE_KEY);
        }
    }
}
