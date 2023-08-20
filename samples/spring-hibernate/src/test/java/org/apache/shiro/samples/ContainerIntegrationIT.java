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
package org.apache.shiro.samples;

import org.apache.shiro.testing.web.AbstractContainerIT;
import org.htmlunit.ElementNotFoundException;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.io.IOException;


public class ContainerIntegrationIT extends AbstractContainerIT {

    protected final WebClient webClient = new WebClient();

    @BeforeEach
    public void logOut() throws IOException {
        // Make sure we are logged out
        final HtmlPage homePage = webClient.getPage(getBaseUri());
        try {
            homePage.getAnchorByHref("/s/logout").click();
        }
        catch (ElementNotFoundException e) {
            //Ignore
        }
    }

    @Test
    void logIn() throws FailingHttpStatusCodeException, IOException, InterruptedException {

        HtmlPage page = webClient.getPage(getBaseUri() + "s/login");
        HtmlForm form = page.getFormByName("loginForm");
        form.<HtmlInput>getInputByName("username").setValueAttribute("admin");
        form.<HtmlInput>getInputByName("password").setValueAttribute("admin");
        page = form.<HtmlInput>getInputByValue("Login").click();
        // This'll throw an exception if not logged in
        page.getAnchorByHref("/s/logout");
    }
}
