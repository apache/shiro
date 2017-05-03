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
package org.apache.shiro.spring.boot.autoconfigure;

import org.apache.shiro.spring.boot.autoconfigure.exception.NoRealmBeanConfiguredException;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

public class ShiroNoRealmConfiguredFailureAnalyzer extends AbstractFailureAnalyzer<NoRealmBeanConfiguredException> {
 
 	@Override
 	protected FailureAnalysis analyze(Throwable rootFailure, NoRealmBeanConfiguredException cause) {
 		return new FailureAnalysis( "No bean of type 'org.apache.shiro.realm.Realm' found.", "Please create bean of type 'Realm' or add a shiro.ini in the root classpath (src/main/resources/shiro.ini) or in the META-INF folder (src/main/resources/META-INF/shiro.ini).", cause);
 	}
 
 }
