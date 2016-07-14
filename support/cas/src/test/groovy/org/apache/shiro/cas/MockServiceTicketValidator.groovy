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
package org.apache.shiro.cas

import org.apache.shiro.util.StringUtils
import org.jasig.cas.client.authentication.AttributePrincipalImpl
import org.jasig.cas.client.validation.Assertion
import org.jasig.cas.client.validation.AssertionImpl
import org.jasig.cas.client.validation.TicketValidationException
import org.jasig.cas.client.validation.TicketValidator

/**
 * @since 1.2
 * @see <a href="https://github.com/bujiio/buji-pac4j">buji-pac4j</a>
 * @deprecated replaced with Shiro integration in <a href="https://github.com/bujiio/buji-pac4j">buji-pac4j</a>.
 */
@Deprecated
class MockServiceTicketValidator implements TicketValidator {

    /**
     * Returns different assertions according to the ticket input. The format of the mock ticket must be :
     * key1=value1,key2=value2,...,keyN=valueN. If keyX is $, valueX is considered to be the name of the principal, otherwise (keyX, valueX)
     * is considered to be an attribute of the principal.
     */
    public Assertion validate(String ticket, String service) throws TicketValidationException {
        String name = null;
        def attributes = [:]
        String[] elements = StringUtils.split(ticket, '|' as char);
        int length = elements.length;
        for (int i = 0; i < length; i++) {
            String[] pair = StringUtils.split(elements[i], '=' as char);
            String key = pair[0].trim();
            String value = pair[1].trim();
            if ('$'.equals(key)) {
                name = value;
            } else {
                attributes.put(key, value);
            }
        }
        AttributePrincipalImpl attributePrincipalImpl = new AttributePrincipalImpl(name, attributes);
        return new AssertionImpl(attributePrincipalImpl, [:]);

    }
}
