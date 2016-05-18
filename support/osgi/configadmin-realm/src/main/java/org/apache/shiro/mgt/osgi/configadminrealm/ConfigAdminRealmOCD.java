/*
 * Copyright 2016 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.mgt.osgi.configadminrealm;

import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 *
 * @author mnn
 */
@ObjectClassDefinition(name = "ConfigAdminRealm", id = "org.apache.shiro.realm.configadminrealm", pid = "org.apache.shiro.realm.configadminrealm")
@interface ConfigAdminRealmOCD {
  String[] user() default "shiro/shiro,shiro";
  String[] role() default "shiro/shiro";
}
