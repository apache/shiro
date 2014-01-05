package org.apache.shiro.hazelcast;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;

/**
 * Constructs and returns an embedded Hazelcast cluster node that can be a peer to other Hazelcast cluster members.
 * <p/>
 * <b>Note:</b> this implementation should only be used if you want to start an embedded Hazelcast server node within
 * the same JVM as your Shiro-enabled application.  If your application should be a standard client to a Hazelcast
 * cluster, use the {@link ClientHazelcastInstanceFactory} instead.
 * <p/>
 * Most Shiro-enabled applications are likely to be clients to a Hazelcast cluster since being a full cache server node
 * (cluster peer) imposes additional memory, threading and communication requirements that might not be suitable for
 * apps with other dedicated workloads (e.g. handling requests).  In these cases, it is likely that
 * the {@link ClientHazelcastInstanceFactory} should be used instead to connect to the cluster, instead of operating
 * as a full server cluster node (peer).
 * <p/>
 * For more information on embedded/server node configuration, see the
 * <a href="http://hazelcast.org/docs/3.0/manual/html-single/#Config">Hazelcast server configuration documentation</a>.
 *
 * @see ClientHazelcastInstanceFactory
 */
public class EmbeddedHazelcastInstanceFactory extends HazelcastInstanceFactory {

    private Config config;

    /**
     * Instantiates the factory with a new {@link Config}, ready to be configured.
     */
    public EmbeddedHazelcastInstanceFactory() {
        this.config = new Config();
    }

    /**
     * Returns the {@link Config} object that represents the configuration to be used when creating a new embedded
     * server node {@link HazelcastInstance}.
     * <p/>
     * If using {@code shiro.ini}, you can reference this property by name and then chain config statements easily to
     * reduce configuration.  For example:
     * <pre>
     * [main]
     * ...
     * hazelcast = org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory
     * hazelcast.config.groupConfig.name = myClusterGroupName
     * hazelcast.config.networkConfig.joinConfig.multicastConfig.enabled = false
     * hazelcast.config.networkConfig.joinConfig.tcpIpConfig.members = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * </pre>
     * <p>or, you can configure the object separately and then inject it by reference. For example:</p>
     * <pre>
     * [main]
     * hazelcastConfig = com.hazelcast.config.Config
     * hazelcastConfig.groupConfig.name = myClusterGroupName
     * hazelcastConfig.networkConfig.joinConfig.multicastConfig.enabled = false
     * hazelcastConfig.networkConfig.joinConfig.tcpIpConfig.members = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * ...
     * hazelcast = org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory
     * hazelcast.config = $hazelcastConfig
     * </pre>
     *
     * @return the config to be used to customize configuration
     */
    public Config getConfig() {
        return config;
    }


    /**
     * Sets the {@link Config} object that represents the configuration to be used when creating a new embedded
     * server node {@link HazelcastInstance}.
     * <p/>
     * If using {@code shiro.ini}, you can reference this property by name and then chain config statements easily to
     * reduce configuration.  For example:
     * <pre>
     * [main]
     * ...
     * hazelcast = org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory
     * hazelcast.config.groupConfig.name = myClusterGroupName
     * hazelcast.config.networkConfig.joinConfig.multicastConfig.enabled = false
     * hazelcast.config.networkConfig.joinConfig.tcpIpConfig.members = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * </pre>
     * <p>or, you can configure the object separately and then inject it by reference. For example:</p>
     * <pre>
     * [main]
     * hazelcastConfig = com.hazelcast.config.Config
     * hazelcastConfig.groupConfig.name = myClusterGroupName
     * hazelcastConfig.networkConfig.joinConfig.multicastConfig.enabled = false
     * hazelcastConfig.networkConfig.joinConfig.tcpIpConfig.members = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * ...
     * hazelcast = org.apache.shiro.hazelcast.EmbeddedHazelcastInstanceFactory
     * hazelcast.config = $hazelcastConfig
     * </pre>
     * @param config the config to be used to customize configuration
     */
    public void setConfig(Config config) {
        this.config = config;
    }

    /**
     * Creates a new client {@code HazelcastInstance} via
     * <pre>
     * return Hazelcast.newHazelcastInstance(this.config);
     * </pre>
     *
     * @return a new client {@code HazelcastInstance}
     */
    @Override
    protected HazelcastInstance createInstance() {
        return Hazelcast.newHazelcastInstance(this.config);
    }
}
