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

import com.hazelcast.core.HazelcastInstance;
import org.apache.shiro.ShiroException;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MapCache;
import org.apache.shiro.util.Initializable;

import java.util.Map;

/**
 * A {@code CacheManager} implementation backed by <a href="http://www.hazelcast.com/">Hazelcast</a>,
 * &quot;an open source clustering and highly scalable data distribution platform for Java&quot;
 * <p/>
 * This implementation interacts with a {@link HazelcastInstance} to
 * {@link HazelcastInstance#getMap(String) acquire} named {@link java.util.concurrent.ConcurrentMap ConcurrentMap}
 * instances.  Those clustered/distributed Map instances are then wrapped and made available to {@code CacheManager}
 * callers as {@link MapCache} instances via {@link #getCache(String)}.
 * <h3>Configuration</h3>
 * This implementation's backing {@code HazelcastInstance} must be specified by calling
 * {@link #setHazelcastInstance(com.hazelcast.core.HazelcastInstance) setHazelcastInstance}, either directly or via
 * Dependency Injection (shiro.ini, Spring, Guice, etc).
 * <p/>
 * DependencyInjection environments will likely find using either the
 * {@link org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory} or the {@link org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory} factory implementations
 * convenient for specifying Hazelcast configuration that will be used to create the {@link HazelcastInstance}.
 * <h4>As a Hazelcast Client</h4>
 * <p>If your Shiro-enabled application is a client to a Hazelcast cluster, you will likely want to use the
 * {@link org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory} to create a client hazelcast instance.  For example, if using
 * {@code shiro.ini}:<p/>
 * <pre>
 * hazelcast = org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory
 * hazelcast.config.groupConfig.name = myClusterGroupName
 * hazelcast.config.addresses = 192.168.1.1, 192.168.1.2, 192.168.1.3
 *
 * cacheManager = org.apache.shiro.hazelcast.cache.HazelcastCacheManager
 * cacheManager.hazelcastInstance = $hazelcast
 * </pre>
 * <h4>As an Embedded Hazelcast Node</h4>
 * <p>If, instead of being a client to a Hazelcast cluster, you want your application to run with an embedded Hazelcast
 * server node (or be a server node peer to other server nodes), use the
 * {@link org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory} instead.  For example:<p/>
 * <pre>
 * [main]
 * hazelcast = org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory
 * hazelcast.config.groupConfig.name = myClusterGroupName
 * hazelcast.config.networkConfig.joinConfig.multicastConfig.enabled = false
 * hazelcast.config.networkConfig.joinConfig.tcpIpConfig.members = 192.168.1.1, 192.168.1.2, 192.168.1.3
 *
 * cacheManager = org.apache.shiro.hazelcast.cache.HazelcastCacheManager
 * cacheManager.hazelcastInstance = $hazelcast
 * </pre>
 *
 * @see org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory
 * @see org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory
 *
 * @since 1.3
 */
public class HazelcastCacheManager implements CacheManager, Initializable {

    private HazelcastInstance hazelcastInstance;

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
     * @see #assertHazlecastInstance() ()
     *
     */
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {
        HazelcastInstance instance = assertHazlecastInstance();
        Map<K, V> map = instance.getMap(name); //returned map is a ConcurrentMap
        return new MapCache<K, V>(name, map);
    }

    /**
     * Asserts that this implementation has a backing {@link HazelcastInstance}, and if not, throws a
     * {@link CacheException}.
     *
     * @see HazelcastInstance
     */
    protected final HazelcastInstance assertHazlecastInstance() throws CacheException {
        if (this.hazelcastInstance == null) {
            throw new CacheException("The " + getClass().getName() + " instance must be configured with a HazelcastInstance instance before it can be used.");
        }
        return this.hazelcastInstance;
    }

    /**
     * Asserts that a {@link #getHazelcastInstance() hazelcastInstance} has been specified.
     *
     * @throws ShiroException if the {@code hazelcastInstance} has not been specified.
     * @see HazelcastInstance
     */
    public void init() throws ShiroException {
        assertHazlecastInstance();
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
}
