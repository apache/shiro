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
package org.apache.shiro.cdi;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardEngine;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.core.StandardService;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.tomee.embedded.Configuration;
import org.apache.tomee.embedded.junit.TomEEEmbeddedRule;
import org.apache.webbeans.inject.OWBInjector;
import org.apache.webbeans.web.lifecycle.test.MockHttpSession;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.spi.CDI;
import javax.inject.Inject;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import java.io.UnsupportedEncodingException;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;
import static javax.ws.rs.core.MediaType.TEXT_PLAIN_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class CDIIT {
    @Parameterized.Parameters
    public static Case[] parameters() {
        return new Case[]{
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        test.service.authenticated();
                    }
                }),
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        test.service.user();
                    }
                }),
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        test.service.permTest();
                    }
                }),
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        test.service.roleTest();
                    }
                }),
                new Case(null, null, new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        test.service.guest();
                    }
                }),
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        try {
                            test.service.role2Test();
                            fail();
                        } catch (final ShiroException se) {
                            // ok
                        }
                    }
                }),
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        try {
                            test.service.perm2Test();
                            fail();
                        } catch (final ShiroException se) {
                            // ok
                        }
                    }
                }),
                new Case("user", "pwd", new Consumer() {
                    @Override
                    public void accept(final CDIIT test) {
                        final Client client = ClientBuilder.newClient();
                        try {
                            assertEquals("ok", client.target("http://localhost:" + CONTAINER.getConfiguration().getHttpPort())
                                    .path("service/user")
                                    .request(TEXT_PLAIN_TYPE)
                                    .header("Authorization", "Basic " + org.apache.commons.codec.binary.Base64.encodeBase64String("user:pwd".getBytes("UTF-8")))
                                    .get(String.class));
                        } catch (final UnsupportedEncodingException e) {
                            throw new IllegalStateException("more than unlikely;");
                        } finally {
                            client.close();
                        }
                    }
                }),
        };
    }

    @ClassRule // start once for the whole class
    public static final TomEEEmbeddedRule CONTAINER = new TomEEEmbeddedRule(new Configuration().randomHttpPort(), "");

    @Parameterized.Parameter
    public Case testCase;

    @Inject
    private SecurityManager manager;

    @Inject
    private Service service;

    @Before
    public void inject() { // rude but efficient way to get injections there, avoids another dependency or tomee internal
        OWBInjector.inject(CDI.current().getBeanManager(), this, null);
    }

    @Test
    public void run() {
        // fake a http request since shiro-web needs it by default
        ThreadContext.bind(manager);
        final DefaultWebSubjectContext context = new DefaultWebSubjectContext();
        final Request request = new Request() {
            private final HttpSession session = new MockHttpSession();
            private final Context context = new StandardContext() {
                {
                    setParent(new StandardHost() {{
                        setParent(new StandardEngine() {{
                            setService(new StandardService());
                        }});
                    }});
                    setCookieProcessor(new Rfc6265CookieProcessor());
                }

                @Override
                public String getPath() {
                    return "/app";
                }
            };

            @Override
            public Context getContext() {
                return context;
            }

            @Override
            public HttpSession getSession() {
                return session;
            }
        };
        final org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        coyoteRequest.requestURI().setString("/test");
        request.setCoyoteRequest(coyoteRequest);
        request.setRemoteHost("localhost");
        request.setRemoteAddr("127.0.0.1");
        context.setServletRequest(request);

        final Response response = new Response();
        response.setConnector(new Connector());
        response.setCoyoteResponse(new org.apache.coyote.Response());
        context.setServletResponse(response);
        final Subject subject = manager.createSubject(context);
        ThreadContext.bind(subject);
        if (testCase.user != null) {
            // finally login
            subject.login(new UsernamePasswordToken(testCase.user, testCase.password));
        }
        try {
            testCase.test.accept(this);
        } finally {
            if (testCase.user != null) {
                subject.logout();
            }
            ThreadContext.remove();
        }
    }

    private static class Case {
        private final String user;
        private final String password;
        private final Consumer test;

        private Case(final String user, final String password, final Consumer test) {
            this.user = user;
            this.password = password;
            this.test = test;
        }
    }

    interface Consumer {
        void accept(CDIIT test);
    }

    @Path("service")
    @ApplicationScoped
    public static class Service {
        @RequiresRoles("ptest")
        public void role2Test() {
        }

        @RequiresRoles("rtest")
        public void roleTest() {
        }

        @RequiresPermissions("ptest")
        public void permTest() {
        }

        @RequiresPermissions("rtest")
        public void perm2Test() {
        }

        @RequiresGuest
        public void guest() {
        }

        @RequiresUser
        @GET
        @Path("user")
        @Produces(TEXT_PLAIN)
        public String user() {
            return "ok";
        }

        @RequiresAuthentication
        public void authenticated() {
        }
    }
}
