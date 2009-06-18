<%--
  ~ Licensed to the Apache Software Foundation (ASF) under one
  ~ or more contributor license agreements.  See the NOTICE file
  ~ distributed with this work for additional information
  ~ regarding copyright ownership.  The ASF licenses this file
  ~ to you under the Apache License, Version 2.0 (the
  ~ "License"); you may not use this file except in compliance
  ~ with the License.  You may obtain a copy of the License at
  ~
  ~     http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>
<%@ page contentType="application/x-java-jnlp-file" %>

<?xml version="1.0" encoding="utf-8"?>
<!-- JNLP File for Shiro Sample Application -->
<jnlp spec="1.0+" codebase="${codebaseUrl}">
    <information>
        <title>Apache Shiro Sample Application</title>
        <vendor>Apache Shiro</vendor>
        <homepage href="http://shiro.apache.org"/>
        <description>Apache Shiro Sample Application</description>
        <description kind="short">A webstart application used to demonstrate Apache Shiro session and security
            management.
        </description>
        <icon kind="splash" href="logo.png"/>
        <offline-allowed/>
    </information>
    <security>
        <all-permissions/>
    </security>
    <resources>
        <j2se version="1.5"/>
        <jar href="shiro-spring-sample.jar"/>
        <jar href="shiro-all.jar"/>
        <jar href="spring.jar"/>
        <jar href="slf4j-api.jar"/>
        <property name="shiro.session.id" value="${sessionId}"/>
    </resources>
    <application-desc main-class="org.apache.shiro.samples.spring.ui.WebStartDriver"/>
</jnlp>
