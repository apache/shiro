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
package org.apache.shiro.openid4j;

import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;

import java.util.Collection;
import java.util.List;

/**
 * Default implementation of the {@link OpenIdService} interface.
 *
 * @since 1.2
 */
public class DefaultOpenIdService implements OpenIdService {

    private ConsumerManager consumerManager;
    private DiscoveryIdResolver discoveryIdResolver;
    private Collection<MessageExtensionFactory> messageExtensionFactories;


    public DefaultOpenIdService() {
        try {
            //The ConsumerManager class is frustrating - at the time of this implementation
            //(2011.02.18), this constructor's source code never throws a ConsumerException - probably left in
            //place to be backwards compatible with a previous release that did throw that exception.
            //Another failing of checked exceptions and not programming to interfaces...
            this.consumerManager = new ConsumerManager();
        } catch (ConsumerException e) {
            throw new IllegalStateException(e);
        }
    }

    public ConsumerManager getConsumerManager() {
        return consumerManager;
    }

    public void setConsumerManager(ConsumerManager consumerManager) {
        this.consumerManager = consumerManager;
    }

    public DiscoveryIdResolver getDiscoveryIdResolver() {
        return discoveryIdResolver;
    }

    public void setDiscoveryIdResolver(DiscoveryIdResolver discoveryIdResolver) {
        this.discoveryIdResolver = discoveryIdResolver;
    }

    public Collection<MessageExtensionFactory> getMessageExtensionFactories() {
        return messageExtensionFactories;
    }

    public void setMessageExtensionFactories(Collection<MessageExtensionFactory> messageExtensionFactories) {
        this.messageExtensionFactories = messageExtensionFactories;
    }

    public ConstructedRequest constructRequest(String providerId, String responseUrl) throws OpenIdException {
        String discoveryId = getDiscoveryId(providerId);

        DiscoveryInformation discoveryInfo = getDiscoveryInfo(discoveryId, providerId);

        AuthRequest request = createRequest(discoveryInfo, responseUrl);

        addExtensions(request, discoveryInfo, providerId, discoveryId);

        return createConstructedRequest(request, discoveryInfo, providerId, discoveryId);
    }

    private void addExtensions(AuthRequest request, DiscoveryInformation info, String serviceId, String discoveryId) {
        if (!CollectionUtils.isEmpty(this.messageExtensionFactories)) {
            for( MessageExtensionFactory factory : this.messageExtensionFactories ) {
                MessageExtension extension = factory.createMessageExtension(request, info, serviceId, discoveryId);
                if (extension != null) {
                    try {
                        request.addExtension(extension);
                    } catch (MessageException e) {
                        String msg = "Unable to add message extension.";
                        throw new OpenIdException(msg, e);
                    }
                }
            }
        }
    }

    protected String getDiscoveryId(String providerId) {
        String discoveryId = providerId;
        if (this.discoveryIdResolver != null) {
            discoveryId = this.discoveryIdResolver.resolveDiscoveryId(providerId);
            if (!StringUtils.hasText(discoveryId)) {
                throw new IllegalStateException("DiscoveryIdResolver returned a null, blank or empty string.");
            }
        } else {
            if (!StringUtils.hasText(providerId)) {
                throw new IllegalArgumentException("providerId argument cannot be null, empty or blank.");
            }
        }
        return discoveryId;
    }

    protected DiscoveryInformation getDiscoveryInfo(String discoveryId, String providerId) throws DiscoveryException {
        try {
            List discoveries = consumerManager.discover(discoveryId);
            return consumerManager.associate(discoveries);
        } catch (OpenIDException e) {
            String msg = "Unable to discover OpenId Provider based on resolved discoveryId '" + discoveryId + "' " +
                    "(specified providerId '" + providerId + "')";
            throw new DiscoveryException(msg, e);
        }
    }

    protected AuthRequest createRequest(DiscoveryInformation info, String responseUrl) throws OpenIdException {
        try {
            return consumerManager.authenticate(info, responseUrl);
        } catch (OpenIDException e) {
            throw new OpenIdException("Unable to create AuthRequest.", e);
        }
    }

    protected ConstructedRequest createConstructedRequest(AuthRequest request, DiscoveryInformation info,
                                                          String providerId, String discoveryId) {
        return new SimpleConstructedRequest(request, info);
    }
}
