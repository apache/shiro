package org.apache.shiro.hazelcast;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.core.HazelcastInstance;

/**
 * Constructs and returns a <a href="http://www.hazelcast.org/docs/3.0/manual/html-single/#JavaClient">Hazelcast client</a>
 * that can be used to interact with Hazelcast cluster members.
 * <p/>
 * This implementation is likely the one that most Shiro-enabled applications will use: most applications are probably
 * not suited to be full cache cluster members because of the additional memory and communication requirements that
 * would impose on the application, and instead are likely to be only clients to the cache cluster.
 * <p/>
 * If you *do* however wish to have your application be a peer (full) cache cluster node - for example, maybe you are
 * running an application in 'embedded' or 'standalone' mode and don't want to connect to external cache nodes - use the
 * {@link EmbeddedHazelcastInstanceFactory} instead.
 *
 * @see EmbeddedHazelcastInstanceFactory
 */
public class ClientHazelcastInstanceFactory extends HazelcastInstanceFactory {

    private ClientConfig config;

    /**
     * Instantiates the factory with a new {@link ClientConfig}, ready to be configured.
     */
    public ClientHazelcastInstanceFactory() {
        this.config = new ClientConfig();
    }

    /**
     * Returns the {@link ClientConfig} object that represents the configuration to be used when creating a new client
     * {@link HazelcastInstance}.
     * <p/>
     * If using {@code shiro.ini}, you can reference this property by name and then chain config statements easily to
     * reduce configuration.  For example:
     * <pre>
     * [main]
     * ...
     * hazelcast = org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory
     * hazelcast.config.groupConfig.name = myClusterGroupName
     * hazelcast.config.addresses = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * </pre>
     * <p>or, you can configure the object separately and then inject it by reference. For example:</p>
     * <pre>
     * [main]
     * hazelcastConfig = com.hazelcast.client.config.ClientConfig
     * hazelcastConfig.groupConfig.name = myClusterGroupName
     * hazelcastConfig.addresses = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * ...
     * hazelcast = org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory
     * hazelcast.config = $hazelcastConfig
     * </pre>
     *
     * @return the clientConfig to be used to customize configuration
     */
    public ClientConfig getConfig() {
        return config;
    }

    /**
     * Sets the {@link ClientConfig} object that represents the configuration to be used when creating a new client
     * {@link HazelcastInstance}.
     * <p/>
     * If using {@code shiro.ini}, you can reference this property by name and then chain config statements easily to
     * reduce configuration.  For example:
     * <pre>
     * [main]
     * ...
     * hazelcast = org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory
     * hazelcast.config.groupConfig.name = myClusterGroupName
     * hazelcast.config.addresses = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * </pre>
     * <p>or, you can configure the object separately and then inject it by reference. For example:</p>
     * <pre>
     * [main]
     * hazelcastConfig = com.hazelcast.client.config.ClientConfig
     * hazelcastConfig.groupConfig.name = myClusterGroupName
     * hazelcastConfig.addresses = 192.168.1.1, 192.168.1.2, 192.168.1.3
     * ...
     * hazelcast = org.apache.shiro.hazelcast.ClientHazelcastInstanceFactory
     * hazelcast.config = $hazelcastConfig
     * </pre>
     *
     * @param config the config object that represents the configuration to be used when creating a new client
     *               {@link HazelcastInstance}.
     */
    public void setConfig(ClientConfig config) {
        this.config = config;
    }

    /**
     * Creates a new client {@code HazelcastInstance} via
     * <pre>
     * return HazelcastClient.newHazelcastClient(this.config);
     * </pre>
     *
     * @return a new client {@code HazelcastInstance}
     */
    @Override
    protected HazelcastInstance createInstance() {
        return HazelcastClient.newHazelcastClient(this.config);
    }
}
