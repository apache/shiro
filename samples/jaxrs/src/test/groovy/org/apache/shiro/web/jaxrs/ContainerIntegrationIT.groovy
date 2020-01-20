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
package org.apache.shiro.web.jaxrs

import org.apache.shiro.testing.web.AbstractContainerIT
import org.junit.Test;

import static com.jayway.restassured.RestAssured.*
import static org.hamcrest.Matchers.*

public class ContainerIntegrationIT extends AbstractContainerIT {

    @Test
    void testNoAuthResource() {

        get(getBaseUri() + "say")
            .then()
                .assertThat()
                .statusCode(is(200)).and()
                .body(equalTo("Hello!"))
    }

    @Test
    void testNoAuthResourceAsync() {

        get(getBaseUri() + "say/async")
                .then()
                .assertThat()
                .statusCode(is(200)).and()
                .body(equalTo("Hello!"))
    }

    @Test
    void testSecuredRequiresAuthentication() {

        get(getBaseUri() + "secure/RequiresAuthentication")
            .then()
                .assertThat().statusCode(is(401))

        given()
            .header("Authorization", getBasicAuthorizationHeaderValue("root", "secret"))
        .when()
            .get(getBaseUri() + "secure/RequiresAuthentication")
        .then()
            .assertThat()
                .statusCode(is(200)).and()
                .body(equalTo("protected"))
    }

    @Test
    void testSecuredRequiresUser() {

        get(getBaseUri() + "secure/RequiresUser")
            .then()
                .assertThat().statusCode(is(401))

        given()
            .header("Authorization", getBasicAuthorizationHeaderValue("root", "secret"))
        .when()
            .get(getBaseUri() + "secure/RequiresUser")
        .then()
            .assertThat()
                .statusCode(is(200)).and()
                .body(equalTo("protected"))
    }

    @Test
    void testSecuredRequiresRoles() {

        get(getBaseUri() + "secure/RequiresRoles")
            .then()
                .assertThat().statusCode(is(401))

        given()
                .header("Authorization", getBasicAuthorizationHeaderValue("guest", "guest"))
        .when()
            .get(getBaseUri() + "secure/RequiresRoles")
        .then()
            .assertThat()
                .statusCode(is(403)).and()

        given()
            .header("Authorization", getBasicAuthorizationHeaderValue("root", "secret"))
        .when()
            .get(getBaseUri() + "secure/RequiresRoles")
        .then()
            .assertThat()
                .statusCode(is(200)).and()
                .body(equalTo("protected"))
    }

    @Test
    void testSecuredRequiresPermissions() {

        get(getBaseUri() + "secure/RequiresPermissions")
            .then()
                .assertThat().statusCode(is(401))

        given()
            .header("Authorization", getBasicAuthorizationHeaderValue("guest", "guest"))
        .when()
            .get(getBaseUri() + "secure/RequiresPermissions")
        .then()
            .assertThat()
                .statusCode(is(403)).and()

        given()
            .header("Authorization", getBasicAuthorizationHeaderValue("lonestarr", "vespa"))
        .when()
            .get(getBaseUri() + "secure/RequiresPermissions")
        .then()
            .assertThat()
                .statusCode(is(200)).and()
                .body(equalTo("protected"))
    }

    @Test
    void testSecuredRequiresGuest() {

        get(getBaseUri() + "secure/RequiresGuest")
            .then()
                .assertThat()
                    .statusCode(is(200)).and()
                    .body(equalTo("not protected"))
    }

}
