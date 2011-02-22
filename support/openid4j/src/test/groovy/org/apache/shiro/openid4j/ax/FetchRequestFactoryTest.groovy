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
package org.apache.shiro.openid4j.ax

import org.openid4java.message.ax.FetchRequest

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: 2/21/11
 * Time: 10:04 PM
 * To change this template use File | Settings | File Templates.
 */
class FetchRequestFactoryTest extends GroovyTestCase {

    void testCreateWithProviderAttributes() {

        FetchRequestFactory factory = new FetchRequestFactory();

        factory.providerAttributes.google = "email[count=1], firstName[required=true], lastName"

        FetchRequest request = factory.createMessageExtension(null, null, "google", null);

        assertNotNull request
        def list = request.getParameters();
        System.out.println(list);

    }


}
