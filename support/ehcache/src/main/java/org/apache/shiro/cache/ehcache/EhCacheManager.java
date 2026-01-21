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
package org.apache.shiro.cache.ehcache;

import java.io.Serializable;
import java.net.URL;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.lang.io.ResourceUtils;
import org.apache.shiro.lang.util.Destroyable;
import org.apache.shiro.lang.util.Initializable;
import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.xml.XmlConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;

/**
 * Shiro {@code CacheManager} implementation utilizing the Ehcache framework for all cache functionality.
 * <p/>
 * This class can {@link #setCacheManager(org.ehcache.CacheManager) accept} a manually configured
 * {@link org.ehcache.CacheManager org.ehcache.CacheManager} instance,
 * or an {@code ehcache.xml} path location can be specified instead and one will be constructed. If neither are
 * specified, Shiro's failsafe <code><a href="./ehcache.xml">ehcache.xml</a></code> file will be used by default.
 * <p/>
 * This implementation requires EhCache 1.2 and above. Make sure EhCache 1.1 or earlier
 * is not in the classpath or it will not work.
 * <p/>
 * Please see the <a href="http://ehcache.org" target="_top">Ehcache website</a> for their documentation.
 *
 * @see <a href="http://ehcache.org" target="_top">The Ehcache website</a>
 * @since 0.2
 */
public class EhCacheManager implements CacheManager, Initializable, Destroyable {

    /**
     * This class's private log instance.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EhCacheManager.class);

    /**
     * The EhCache cache manager used by this implementation to create caches.
     */
    protected org.ehcache.CacheManager manager;

    /**
     * Indicates if the CacheManager instance was implicitly/automatically created by this instance, indicating that
     * it should be automatically cleaned up as well on shutdown.
     */
    private boolean cacheManagerImplicitlyCreated;

    /**
     * Classpath file location of the ehcache CacheManager config file.
     */
    private String cacheManagerConfigFile = "classpath:org/apache/shiro/cache/ehcache/ehcache.xml";

    /**
     * Default no argument constructor
     */
    public EhCacheManager() {
    }

    /**
     * Returns the wrapped Ehcache {@link org.ehcache.CacheManager CacheManager} instance.
     *
     * @return the wrapped Ehcache {@link org.ehcache.CacheManager CacheManager} instance.
     */
    public org.ehcache.CacheManager getCacheManager() {
        return manager;
    }

    /**
     * Sets the wrapped Ehcache {@link org.ehcache.CacheManager CacheManager} instance.
     *
     * @param manager the wrapped Ehcache {@link org.ehcache.CacheManager CacheManager} instance.
     */
    public void setCacheManager(org.ehcache.CacheManager manager) {
        this.manager = manager;
    }

    /**
     * Returns the resource location of the config file used to initialize a new
     * EhCache CacheManager instance.  The string can be any resource path supported by the
     * {@link org.apache.shiro.lang.io.ResourceUtils#getInputStreamForPath(String)} call.
     * <p/>
     * This property is ignored if the CacheManager instance is injected directly - that is, it is only used to
     * lazily create a CacheManager if one is not already provided.
     *
     * @return the resource location of the config file used to initialize the wrapped
     * EhCache CacheManager instance.
     */
    public String getCacheManagerConfigFile() {
        return this.cacheManagerConfigFile;
    }

    /**
     * Sets the resource location of the config file used to initialize the wrapped
     * EhCache CacheManager instance.  The string can be any resource path supported by the
     * {@link org.apache.shiro.lang.io.ResourceUtils#getInputStreamForPath(String)} call.
     * <p/>
     * This property is ignored if the CacheManager instance is injected directly - that is, it is only used to
     * lazily create a CacheManager if one is not already provided.
     *
     * @param classpathLocation resource location of the config file used to create the wrapped
     *                          EhCache CacheManager instance.
     */
    public void setCacheManagerConfigFile(String classpathLocation) {
        this.cacheManagerConfigFile = classpathLocation;
    }

    /**
     * Acquires the InputStream for the ehcache configuration file using
     * {@link ResourceUtils#getInputStreamForPath(String) ResourceUtils.getInputStreamForPath} with the
     * path returned from {@link #getCacheManagerConfigFile() getCacheManagerConfigFile()}.
     *
     * @return the InputStream for the ehcache configuration file.
     */
    protected InputStream getCacheManagerConfigFileInputStream() {
        String configFile = getCacheManagerConfigFile();
        try {
            return ResourceUtils.getInputStreamForPath(configFile);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to obtain input stream for cacheManagerConfigFile ["
                    + configFile + "]", e);
        }
    }

    /**
     * Acquires the URL for the ehcache configuration file using
     * {@link ResourceUtils#getURLForPath(String) ResourceUtils.getURLForPath} with the
     * path returned from {@link #getCacheManagerConfigFile() getCacheManagerConfigFile()}.
     *
     * @return the URL for the ehcache configuration file.
     */
    protected URL getCacheManagerConfigFileUrl() {
        final var configFile = getCacheManagerConfigFile();
        try {
            return ResourceUtils.getURLForPath(configFile);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse cacheManagerConfigFile ["
                            + configFile + "]", e);
        }
    }

    /**
     * Loads an existing EhCache from the cache manager, or starts a new cache if one is not found.
     *
     * @param name the name of the cache to load/create.
     */
    @Override
    public final <K, V> Cache<K, V> getCache(String name)
            throws CacheException {

        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Acquiring EhCache instance named [{}]", name);
        }

        try {
            org.ehcache.Cache<K, V> cache = (org.ehcache.Cache<K, V>) ensureCacheManager()
                    .getCache(name, Serializable.class, Serializable.class);
            if (cache == null) {
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("Cache with name '{}' does not yet exist.  Creating now.", name);
                }
                CacheConfiguration<K, V> config = (CacheConfiguration<K, V>) new XmlConfiguration(getCacheManagerConfigFileUrl())
                        .newCacheConfigurationBuilderFromTemplate("default", Serializable.class, Serializable.class)
                        .build();
                cache = manager.createCache(name, config);

                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("Added EhCache named [{}]", name);
                }
            } else {
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("Using existing EHCache named [{}]", name);
                }
            }
            return new EhCache<>(cache);
        } catch (IllegalArgumentException | IllegalStateException | ReflectiveOperationException e) {
            throw new CacheException(e);
        }
    }

    /**
     * Initializes this instance.
     * <p/>
     * If a {@link #setCacheManager CacheManager} has been
     * explicitly set (e.g. via Dependency Injection or programmatically) prior to calling this
     * method, this method does nothing.
     * <p/>
     * However, if no {@code CacheManager} has been set, the default Ehcache singleton will be initialized, where
     * Ehcache will look for an {@code ehcache.xml} file at the root of the classpath.  If one is not found,
     * Ehcache will use its own failsafe configuration file.
     * <p/>
     * Because Shiro cannot use the failsafe defaults (fail-safe expunges cached objects after 2 minutes,
     * something not desirable for Shiro sessions), this class manages an internal default configuration for
     * this case.
     *
     * @throws org.apache.shiro.cache.CacheException if there are any CacheExceptions thrown by EhCache.
     * @see org.ehcache.CacheManager#createCache(String, org.ehcache.config.CacheConfiguration)
     */
    public final void init() throws CacheException {
        ensureCacheManager();
    }

    private org.ehcache.CacheManager ensureCacheManager() {
        try {
            if (this.manager == null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("cacheManager property not set.  Constructing CacheManager instance... ");
                }
                final XmlConfiguration xmlConfig = new XmlConfiguration(getCacheManagerConfigFileUrl());
                this.manager = CacheManagerBuilder.newCacheManager(xmlConfig);
                this.manager.init();
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("instantiated Ehcache CacheManager instance.");
                }
                cacheManagerImplicitlyCreated = true;
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("implicit cacheManager created successfully.");
                }
            }
            return this.manager;
        } catch (Exception e) {
            throw new CacheException(e);
        }
    }

    /**
     * Shuts-down the wrapped Ehcache CacheManager <b>only if implicitly created</b>.
     * <p/>
     * If another component injected
     * a non-null CacheManager into this instance before calling {@link #init() init}, this instance expects that same
     * component to also destroy the CacheManager instance, and it will not attempt to do so.
     */
    public void destroy() {
        if (cacheManagerImplicitlyCreated) {
            try {
                org.ehcache.CacheManager cacheMgr = getCacheManager();
                cacheMgr.close();
            } catch (Throwable t) {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn("Unable to cleanly shutdown implicitly created CacheManager instance.  "
                            + "Ignoring (shutting down)...", t);
                }
            } finally {
                this.manager = null;
                this.cacheManagerImplicitlyCreated = false;
            }
        }
    }

}
