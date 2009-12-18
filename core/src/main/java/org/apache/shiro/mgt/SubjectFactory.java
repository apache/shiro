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
package org.apache.shiro.mgt;

import org.apache.shiro.subject.Subject;

import java.util.Map;

/**
 * A {@code SubjectFactory} is responsible for returning {@link Subject Subject} instances as needed.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface SubjectFactory {

    public static final String SESSION_ID = SubjectFactory.class.getName() + ".SESSION_ID";

    public static final String AUTHENTICATION_TOKEN = SubjectFactory.class.getName() + ".AUTHENTICATION_TOKEN";

    public static final String AUTHENTICATION_INFO = SubjectFactory.class.getName() + ".AUTHENTICATION_INFO";

    public static final String SUBJECT = SubjectFactory.class.getName() + ".SUBJECT";

    public static final String PRINCIPALS = SubjectFactory.class.getName() + ".PRINCIPALS";

    public static final String SESSION = SubjectFactory.class.getName() + ".SESSION";

    public static final String AUTHENTICATED = SubjectFactory.class.getName() + ".AUTHENTICATED";

    public static final String HOST = SubjectFactory.class.getName() + ".HOST";

    /**
     * @deprecated use the {@link #HOST HOST} key instead.  This will be removed prior to 1.0.
     */
    @Deprecated
    public static final String INET_ADDRESS = HOST;

    public static final String SERVLET_REQUEST = SubjectFactory.class.getName() + ".SERVLET_REQUEST";

    public static final String SERVLET_RESPONSE = SubjectFactory.class.getName() + ".SERVLET_RESPONSE";

    /**
     * Creates a new Subject instance reflecting the state of the specified contextual data.  The data would be
     * anything required to required to construct a {@code Subject} instance and its contents can vary based on
     * environment.
     *
     * @param context the contextual data to be used by the implementation to construct an appropriate {@code Subject}
     *                instance.
     * @return a {@code Subject} instance created based on the specified context.
     */
    Subject createSubject(Map context);

}
