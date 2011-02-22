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
package org.apache.shiro.openid4j.ax;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.openid4j.MessageExtensionFactory;
import org.apache.shiro.openid4j.OpenIdException;
import org.apache.shiro.util.StringUtils;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.FetchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * @since 1.2
 */
public class FetchRequestFactory implements MessageExtensionFactory<FetchRequest> {

    private static final Logger log = LoggerFactory.getLogger(FetchRequestFactory.class);

    private Map<String, String> providerAttributes;

    public FetchRequestFactory() {
        this.providerAttributes = new HashMap<String,String>();
    }

    public Map<String, String> getProviderAttributes() {
        return providerAttributes;
    }

    public void setProviderAttributes(Map<String, String> providerAttributes) {
        this.providerAttributes = providerAttributes;
    }

    public FetchRequest createMessageExtension(AuthRequest request, DiscoveryInformation info, String serviceId, String discoveryId) {

        String definition = providerAttributes.get(serviceId);
        if (definition == null) {
            definition = providerAttributes.get(discoveryId);
        }
        if (definition == null) {
            return null;
        }

        String[] attributes = StringUtils.split(definition);
        if (attributes == null || attributes.length == 0) {
            return null;
        }

        FetchRequest fetch = FetchRequest.createFetchRequest();

        //parse the definition by tokenizing it to get the resulting attribute-specific config
        //
        //e.g. for a value of
        //
        //     "email, firstName[required=true], lastName"
        //
        // the resulting token array would equal
        //
        //     { "email", "firstName[required=true]", "lastName" }
        //
        for (String attribute : attributes) {
            //strip the name and extract any attribute-specific config between brackets [ ]
            String[] nameAndConfig = attribute.split("\\[", 2);
            String name = nameAndConfig[0];
            String config = null;

            if (nameAndConfig.length == 2) {
                config = nameAndConfig[1];
                //if there was an open bracket, there was a close bracket, so strip it too:
                config = config.substring(0, config.length() - 1);
            }

            AttributeDefinition ad = toDefinition(name, config);

            try {
                fetch.addAttribute(ad.getName(), ad.getUri(), ad.isRequired(), ad.getCount());
            } catch (MessageException e) {
                throw new OpenIdException("Unable to correctly add 'fetch' attribute.", e);
            }
        }

        return fetch;
    }

    protected AttributeDefinition toDefinition(String name, String config) {

        AttributeProperty prop = AttributeProperty.fromName(name);
        if (prop == null) {
            throw new ConfigurationException("Unable to locate a standard OpenId Attribute property for name '" +
                    name + "'.  Please ensure this name matches one of the constants in the " +
                    AttributeProperty.class.getName() + " enum (name matching is case insensitive).");
        }

        String uri = prop.getUri();
        boolean required = false;
        int count = 0;


        if (config != null) {
            String[] configPairs = StringUtils.split(config);
            for (String pair : configPairs) {
                String nameValue[] = pair.split("\\=", 2);
                if (nameValue.length != 2) {
                    throw new ConfigurationException("OpenId attribute properties with configuration must be " +
                            "comma-delimited name/value pairs.  Each name/value pair must be separated by the " +
                            "equals sign, e.g. nameProp[name1=value1, name2=value2, ...].   The string that " +
                            "caused this error was '" + pair + "'.");
                }
                String pairName = nameValue[0];
                String pairValue = nameValue[1];

                if ("uri".equalsIgnoreCase(pairName)) {
                    uri = pairValue;
                } else if ("required".equalsIgnoreCase(pairName)) {
                    required = Boolean.valueOf(pairValue);
                } else if ("count".equalsIgnoreCase(pairName)) {
                    try {
                        count = Integer.parseInt(pairValue);
                    } catch (NumberFormatException e) {
                        String msg = "Unable to correctly parse 'count' value '" + pairValue + "' for OpenId " +
                                "attribute '" + name + "'";
                        throw new ConfigurationException(msg, e);
                    }
                    if (count < 0) {
                        count = 0;
                    }
                } else {
                    if (log.isWarnEnabled()) {
                        log.warn("Unrecognized configuration name/value pair for OpenId attribute '{}': {}={}",
                                new Object[]{name, pairName, pairValue});
                    }

                }
            }
        }


        return new SimpleAttributeDefinition(prop.name(), uri, required, count);
    }


}
