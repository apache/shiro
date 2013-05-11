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
package org.apache.shiro.spring.security.interceptor;

import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * All the tests in the parent class are run.  This class exists to ensure that Shiro
 * annotations function correctly in Spring applications configured via Spring's AOP namespace
 * &lt;aop:config&gt; style of configuration, as defined in the Spring reference manual:
 * <a href="http://static.springsource.org/spring/docs/3.0.x/spring-framework-reference/html/aop.html#aop-schema">
 * Schema-based AOP support</a>.
 *
 * @since 1.1
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class SchemaAuthorizationAnnotationTest extends AbstractAuthorizationAnnotationTest {
}
