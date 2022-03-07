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
package org.apache.shiro.hazelcast.cache;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MapCache;
import org.apache.shiro.lang.util.Destroyable;
import org.apache.shiro.lang.util.Initializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * A {@code CacheManager} implementation backed by <a href="http://www.hazelcast.com/">Hazelcast</a>,
 * &quot;an open source clustering and highly scalable data distribution platform for Java&quot;
 * <p/>
 * This implementation interacts with a {@link HazelcastInstance} to
 * {@link HazelcastInstance#getMap(String) acquire} named {@link java.util.concurrent.ConcurrentMap ConcurrentMap}
 * instances.  Those clustered/distributed Map instances are then wrapped and made available to {@code CacheManager}
 * callers as {@link MapCache} instances via {@link #getCache(String)}.
 * <h2>Configuration</h2>
 * This implementation's backing {@code HazelcastInstance} can be configured in one of three ways:
 * <ol>
 * <li>Doing nothing and leveraging default Hazelcast configuration mechanisms</li>
 * <li>Supplying an already-existing {@code HazelcastInstance}</li>
 * <li>Supplying a {@link Config} instance and using that to create a new {@code HazelcastInstance}</li>
 * </ol>
 * <h3>Default Configuration</h3>
 * If you simply instantiate a {@code HazelcastCacheManager} and do nothing further, its backing
 * {@link HazelcastInstance} instance will be created automatically by calling
 * {@link Hazelcast#newHazelcastInstance(com.hazelcast.config.Config) Hazelcast.newHazelcastInstance(null)}.
 * <p/>
 * The null argument instructs Hazelcast to use whatever default configuration mechanism it has at its disposal,
 * usually a {@code hazelcast.xml} file at the root of the classpath, or if that is not present, the
 * {@code hazelcast-default.xml} file contained in the Hazelcast {@code .jar} file itself.
 * <p/>
 * <h3>An existing {@code HazelcastInstance}</h3>
 * If you have created a {@code HazelcastInstance} outside of Shiro's knowledge/control, you can simply configure it
 * to be used by calling {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) setHazelcastInstance}.
 * <p/>
 * <h3>A {@link Config} instance</h3>
 * If you do not want to use the above two options, you can have programmatic control over all of Hazelcast's
 * configuration by <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">creating and configuring a
 * Config instance</a>.
 * <p/>
 * Once constructed, you can set it via {@link #setConfig(com.hazelcast.config.Config) setConfig(config)}. This config
 * instance will be used to acquire a new Hazelcast instance by calling
 * {@link Hazelcast#newHazelcastInstance(Config) Hazelcast.newHazelcastInstance(config)}
 *
 * @see <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">Hazelcast Configuration Documentation</a>
 * @since 1.3
 */
public class HazelcastCacheManager implements CacheManager, Initializable, Destroyable {

    public static final Logger log = LoggerFactory.getLogger(HazelcastCacheManager.class);

    private boolean implicitlyCreated = false;
    private HazelcastInstance hazelcastInstance;
    private Config config;

    /**
     * Returns a {@link MapCache} instance representing the named Hazelcast-managed
     * {@link com.hazelcast.core.IMap IMap}.  The Hazelcast Map is obtained by calling
     * {@link HazelcastInstance#getMap(String) hazelcastInstance.getMap(name)}.
     *
     * @param name the name of the cache to acquire.
     * @param <K> the type of map key
     * @param <V> the type of map value
     * @return a {@link MapCache} instance representing the named Hazelcast-managed {@link com.hazelcast.core.IMap IMap}.
     * @throws CacheException
     * @see HazelcastInstance#getMap(String)
     * @see #ensureHazelcastInstance()
     *
     */
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {
        Map<K, V> map = ensureHazelcastInstance().getMap(name); //returned map is a ConcurrentMap
        return new MapCache<K, V>(name, map);
    }

    /**
     * Ensures that this implementation has a backing {@link HazelcastInstance}, and if not, implicitly creates one
     * via {@link #createHazelcastInstance()}.
     *
     * @return the backing (potentially newly created) {@code HazelcastInstance}.
     * @see #createHazelcastInstance()
     * @see HazelcastInstance
     */
    protected HazelcastInstance ensureHazelcastInstance() {
        if (this.hazelcastInstance == null) {
            this.hazelcastInstance = createHazelcastInstance();
            this.implicitlyCreated = true;
        }
        return this.hazelcastInstance;
    }

    /**
     * Initializes this instance by {@link #ensureHazelcastInstance() ensuring} there is a backing
     * {@link HazelcastInstance}.
     *
     * @throws ShiroException
     * @see #ensureHazelcastInstance()
     * @see HazelcastInstance
     */
    public void init() throws ShiroException {
        ensureHazelcastInstance();
    }

    /**
     * Implicitly creates and returns a new {@link HazelcastInstance} that will be used to back this implementation.
     * This implementation calls:
     * <pre>
     * return Hazelcast.newHazelcastInstance(this.config);
     * </pre>
     * using any {@link #setConfig(com.hazelcast.config.Config) configured} {@code Config} object.  If no config
     * object has been specified, {@code this.config} will be {@code null}, thereby using Hazelcast's
     * <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">default configuration mechanism</a>.
     * <p/>
     * Can be overridden by subclasses for custom creation behavior.
     *
     * @return a new {@link HazelcastInstance} that will be used to back this implementation
     * @see Hazelcast#newHazelcastInstance(com.hazelcast.config.Config)
     * @see Config
     */
    protected HazelcastInstance createHazelcastInstance() {
        return Hazelcast.newHazelcastInstance(this.config);
    }

    //needed for unit tests only - not part of Shiro's public API

    /**
     * NOT PART OF SHIRO'S ACCESSIBLE API.  DO NOT DEPEND ON THIS.  This method was added for testing purposes only.
     * <p/>
     * Returns {@code true} if this {@code HazelcastCacheManager} instance implicitly created the backing
     * {@code HazelcastInstance}, or {@code false} if one was externally provided via
     * {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) setHazelcastInstance}.
     *
     * @return {@code true} if this {@code HazelcastCacheManager} instance implicitly created the backing
     *         {@code HazelcastInstance}, or {@code false} if one was externally provided via
     *         {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) setHazelcastInstance}.
     */
    protected final boolean isImplicitlyCreated() {
        return this.implicitlyCreated;
    }

    /**
     * Destroys any {@link #ensureHazelcastInstance() implicitly created} backing {@code HazelcastInstance}.  If the
     * backing Hazelcast was not implicitly created (i.e. because it was configured externally and supplied via
     * {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) setHazelcastInstance}), this method does
     * nothing.
     *
     * @throws Exception if there is a problem shutting down
     */
    public void destroy() throws Exception {
        if (this.implicitlyCreated) {
            try {
                this.hazelcastInstance.getLifecycleService().shutdown();
            } catch (Throwable t) {
                if (log.isWarnEnabled()) {
                    log.warn("Unable to cleanly shutdown implicitly created HazelcastInstance.  " +
                            "Ignoring (shutting down)...", t);
                }
            } finally {
                this.hazelcastInstance = null;
                this.implicitlyCreated = false;
            }
        }
    }

    /**
     * Returns the {@code HazelcastInstance} from which named {@link java.util.concurrent.ConcurrentMap ConcurrentMap}
     * instances will be acquired to create {@link MapCache} instances.
     *
     * @return the {@code HazelcastInstance} from which named {@link java.util.concurrent.ConcurrentMap ConcurrentMap}
     *         instances will be acquired to create {@link MapCache} instances.
     */
    public HazelcastInstance getHazelcastInstance() {
        return hazelcastInstance;
    }

    /**
     * Sets the {@code HazelcastInstance} from which named {@link java.util.concurrent.ConcurrentMap ConcurrentMap}
     * instances will be acquired to create {@link MapCache} instances.
     *
     * @param hazelcastInstance the {@code HazelcastInstance} from which named
     *                          {@link java.util.concurrent.ConcurrentMap ConcurrentMap} instances will be acquired to create
     *                          {@link MapCache} instances.
     */
    public void setHazelcastInstance(HazelcastInstance hazelcastInstance) {
        this.hazelcastInstance = hazelcastInstance;
    }

    /**
     * Returns the Hazelcast {@code Config} object to use to create a backing {@code HazelcastInstance} if one is not
     * {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) supplied}, or {@code null} if the
     * default <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">Hazelcast configuration
     * mechanisms</a> will be used.
     *
     * @return the Hazelcast {@code Config} object to use to create a backing {@code HazelcastInstance} if one is not
     *         {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) supplied}, or {@code null} if the
     *         default <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">Hazelcast configuration
     *         mechanisms</a> will be used.
     * @see Hazelcast#newHazelcastInstance(com.hazelcast.config.Config)
     */
    public Config getConfig() {
        return config;
    }

    /**
     * Sets the Hazelcast {@code Config} object to use to create a backing {@code HazelcastInstance} if one is not
     * {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) supplied}.  {@code null} can be set if the
     * default <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">Hazelcast configuration
     * mechanisms</a> will be used.
     *
     * @param config the Hazelcast {@code Config} object to use to create a backing {@code HazelcastInstance} if one is not
     *               {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) supplied}, or {@code null} if the
     *               default <a href="http://www.hazelcast.com/docs/2.5/manual/multi_html/ch12.html">Hazelcast configuration
     *               mechanisms</a> will be used.
     */
    public void setConfig(Config config) {
        this.config = config;
    }

}
