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
package org.apache.shiro.realm.text;

import org.apache.shiro.ShiroException;
import org.apache.shiro.io.ResourceUtils;
import org.apache.shiro.util.Destroyable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


/**
 * A {@link TextConfigurationRealm} that defers all logic to the parent class, but just enables
 * {@link java.util.Properties Properties} based configuration in addition to the parent class's String configuration.
 * <p/>
 * This class allows processing of a single .properties file for user, role, and
 * permission configuration.
 * <p/>
 * The {@link #setResourcePath resourcePath} <em>MUST</em> be set before this realm can be initialized.  You
 * can specify any resource path supported by
 * {@link ResourceUtils#getInputStreamForPath(String) ResourceUtils.getInputStreamForPath} method.
 * <p/>
 * The Properties format understood by this implementation must be written as follows:
 * <p/>
 * Each line's key/value pair represents either a user-to-role(s) mapping <em>or</em> a role-to-permission(s)
 * mapping.
 * <p/>
 * The user-to-role(s) lines have this format:</p>
 * <p/>
 * <code><b>user.</b><em>username</em> = <em>password</em>,role1,role2,...</code></p>
 * <p/>
 * Note that each key is prefixed with the token <b>{@code user.}</b>  Each value must adhere to the
 * the {@link #setUserDefinitions(String) setUserDefinitions(String)} JavaDoc.
 * <p/>
 * The role-to-permission(s) lines have this format:</p>
 * <p/>
 * <code><b>role.</b><em>rolename</em> = <em>permissionDefinition1</em>, <em>permissionDefinition2</em>, ...</code>
 * <p/>
 * where each key is prefixed with the token <b>{@code role.}</b> and the value adheres to the format specified in
 * the {@link #setRoleDefinitions(String) setRoleDefinitions(String)} JavaDoc.
 * <p/>
 * Here is an example of a very simple properties definition that conforms to the above format rules and corresponding
 * method JavaDocs:
 * <p/>
 * <code>user.root = <em>rootPassword</em>,administrator<br/>
 * user.jsmith = <em>jsmithPassword</em>,manager,engineer,employee<br/>
 * user.abrown = <em>abrownPassword</em>,qa,employee<br/>
 * user.djones = <em>djonesPassword</em>,qa,contractor<br/>
 * <br/>
 * role.administrator = *<br/>
 * role.manager = &quot;user:read,write&quot;, file:execute:/usr/local/emailManagers.sh<br/>
 * role.engineer = &quot;file:read,execute:/usr/local/tomcat/bin/startup.sh&quot;<br/>
 * role.employee = application:use:wiki<br/>
 * role.qa = &quot;server:view,start,shutdown,restart:someQaServer&quot;, server:view:someProductionServer<br/>
 * role.contractor = application:use:timesheet</code>
 *
 * @since 0.2
 */
public class PropertiesRealm extends TextConfigurationRealm implements Destroyable, Runnable {

    //TODO - complete JavaDoc

    /*-------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final int DEFAULT_RELOAD_INTERVAL_SECONDS = 10;
    private static final String USERNAME_PREFIX = "user.";
    private static final String ROLENAME_PREFIX = "role.";
    private static final String DEFAULT_RESOURCE_PATH = "classpath:shiro-users.properties";

    /*-------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private static final Logger log = LoggerFactory.getLogger(PropertiesRealm.class);

    protected ExecutorService scheduler = null;
    protected boolean useXmlFormat = false;
    protected String resourcePath = DEFAULT_RESOURCE_PATH;
    protected long fileLastModified;
    protected int reloadIntervalSeconds = DEFAULT_RELOAD_INTERVAL_SECONDS;

    public PropertiesRealm() {
        super();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Determines whether or not the properties XML format should be used.  For more information, see
     * {@link Properties#loadFromXML(java.io.InputStream)}
     *
     * @param useXmlFormat true to use XML or false to use the normal format.  Defaults to false.
     */
    public void setUseXmlFormat(boolean useXmlFormat) {
        this.useXmlFormat = useXmlFormat;
    }

    /**
     * Sets the path of the properties file to load user, role, and permission information from.  The properties
     * file will be loaded using {@link ResourceUtils#getInputStreamForPath(String)} so any convention recongized
     * by that method is accepted here.  For example, to load a file from the classpath use
     * {@code classpath:myfile.properties}; to load a file from disk simply specify the full path; to load
     * a file from a URL use {@code url:www.mysite.com/myfile.properties}.
     *
     * @param resourcePath the path to load the properties file from.  This is a required property.
     */
    public void setResourcePath(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    /**
     * Sets the interval in seconds at which the property file will be checked for changes and reloaded.  If this is
     * set to zero or less, property file reloading will be disabled.  If it is set to 1 or greater, then a
     * separate thread will be created to monitor the propery file for changes and reload the file if it is updated.
     *
     * @param reloadIntervalSeconds the interval in seconds at which the property file should be examined for changes.
     *                              If set to zero or less, reloading is disabled.
     */
    public void setReloadIntervalSeconds(int reloadIntervalSeconds) {
        this.reloadIntervalSeconds = reloadIntervalSeconds;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    @Override
    public void onInit() {
        //TODO - cleanup - this method shouldn't be necessary
        afterRoleCacheSet();
    }

    protected void afterRoleCacheSet() {
        loadProperties();
        //we can only determine if files have been modified at runtime (not classpath entries or urls), so only
        //start the thread in this case:
        if (this.resourcePath.startsWith(ResourceUtils.FILE_PREFIX) && scheduler != null) {
            startReloadThread();
        }
    }

    public void destroy() {
        try {
            if (scheduler != null) {
                scheduler.shutdown();
            }
        } catch (Exception e) {
            if (log.isInfoEnabled()) {
                log.info("Unable to cleanly shutdown Scheduler.  Ignoring (shutting down)...", e);
            }
        }
    }

    protected void startReloadThread() {
        if (this.reloadIntervalSeconds > 0) {
            this.scheduler = Executors.newSingleThreadScheduledExecutor();
            ((ScheduledExecutorService) this.scheduler).scheduleAtFixedRate(this, reloadIntervalSeconds, reloadIntervalSeconds, TimeUnit.SECONDS);
        }
    }

    public void run() {
        try {
            reloadPropertiesIfNecessary();
        } catch (Exception e) {
            if (log.isErrorEnabled()) {
                log.error("Error while reloading property files for realm.", e);
            }
        }
    }

    private void loadProperties() {
        if (resourcePath == null || resourcePath.length() == 0) {
            throw new IllegalStateException("The resourcePath property is not set.  " +
                    "It must be set prior to this realm being initialized.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Loading user security information from file [" + resourcePath + "]...");
        }

        Properties properties = loadProperties(resourcePath);
        createRealmEntitiesFromProperties(properties);
    }

    private Properties loadProperties(String resourcePath) {
        Properties props = new Properties();

        InputStream is = null;
        try {

            if (log.isDebugEnabled()) {
                log.debug("Opening input stream for path [" + resourcePath + "]...");
            }

            is = ResourceUtils.getInputStreamForPath(resourcePath);
            if (useXmlFormat) {

                if (log.isDebugEnabled()) {
                    log.debug("Loading properties from path [" + resourcePath + "] in XML format...");
                }

                props.loadFromXML(is);
            } else {

                if (log.isDebugEnabled()) {
                    log.debug("Loading properties from path [" + resourcePath + "]...");
                }

                props.load(is);
            }

        } catch (IOException e) {
            throw new ShiroException("Error reading properties path [" + resourcePath + "].  " +
                    "Initializing of the realm from this file failed.", e);
        } finally {
            ResourceUtils.close(is);
        }

        return props;
    }


    private void reloadPropertiesIfNecessary() {
        if (isSourceModified()) {
            restart();
        }
    }

    private boolean isSourceModified() {
        //we can only check last modified times on files - classpath and URL entries can't tell us modification times
        return this.resourcePath.startsWith(ResourceUtils.FILE_PREFIX) && isFileModified();
    }

    private boolean isFileModified() {
        File propertyFile = new File(this.resourcePath);
        long currentLastModified = propertyFile.lastModified();
        if (currentLastModified > this.fileLastModified) {
            this.fileLastModified = currentLastModified;
            return true;
        } else {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private void restart() {
        if (resourcePath == null || resourcePath.length() == 0) {
            throw new IllegalStateException("The resourcePath property is not set.  " +
                    "It must be set prior to this realm being initialized.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Loading user security information from file [" + resourcePath + "]...");
        }

        try {
            destroy();
        } catch (Exception e) {
            //ignored
        }
        init();
    }

    @SuppressWarnings("unchecked")
    private void createRealmEntitiesFromProperties(Properties properties) {

        StringBuilder userDefs = new StringBuilder();
        StringBuilder roleDefs = new StringBuilder();

        Enumeration<String> propNames = (Enumeration<String>) properties.propertyNames();

        while (propNames.hasMoreElements()) {

            String key = propNames.nextElement().trim();
            String value = properties.getProperty(key).trim();
            if (log.isTraceEnabled()) {
                log.trace("Processing properties line - key: [" + key + "], value: [" + value + "].");
            }

            if (isUsername(key)) {
                String username = getUsername(key);
                userDefs.append(username).append(" = ").append(value).append("\n");
            } else if (isRolename(key)) {
                String rolename = getRolename(key);
                roleDefs.append(rolename).append(" = ").append(value).append("\n");
            } else {
                String msg = "Encountered unexpected key/value pair.  All keys must be prefixed with either '" +
                        USERNAME_PREFIX + "' or '" + ROLENAME_PREFIX + "'.";
                throw new IllegalStateException(msg);
            }
        }

        setUserDefinitions(userDefs.toString());
        setRoleDefinitions(roleDefs.toString());
        processDefinitions();
    }

    protected String getName(String key, String prefix) {
        return key.substring(prefix.length(), key.length());
    }

    protected boolean isUsername(String key) {
        return key != null && key.startsWith(USERNAME_PREFIX);
    }

    protected boolean isRolename(String key) {
        return key != null && key.startsWith(ROLENAME_PREFIX);
    }

    protected String getUsername(String key) {
        return getName(key, USERNAME_PREFIX);
    }

    protected String getRolename(String key) {
        return getName(key, ROLENAME_PREFIX);
    }
}
