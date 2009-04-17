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
<%@ include file="include.jsp" %>

<html>
<head>
    <link type="text/css" rel="stylesheet" href="<c:url value="/style.css"/>"/>
</head>
<body>

<h1>Apache Ki Quickstart</h1>

<p>Hi <ki:guest>Guest</ki:guest><ki:user><ki:principal/></ki:user>!
    ( <ki:user><a href="<c:url value="/logout.jsp"/>">Log out</a></ki:user>
    <ki:guest><a href="<c:url value="/login.jsp"/>">Log in</a> (sample accounts provided)</ki:guest> )
</p>

<p>Welcome to the Apache Ki Quickstart sample application.
    This page represents the home page of any web application.</p>

<ki:user><p>Visit your <a href="<c:url value="/account"/>">account page</a>.</p></ki:user>
<ki:guest><p>If you want to access the user-only <a href="<c:url value="/account"/>">account page</a>,
    you will need to log-in first.</p></ki:guest>

<h2>Roles</h2>

<p>To show some taglibs, here are the roles you have and don't have. Log out and log back in under different user
    accounts to see different roles.</p>

<h3>Roles you have</h3>

<p>
    <ki:hasRole name="root">root<br/></ki:hasRole>
    <ki:hasRole name="president">president<br/></ki:hasRole>
    <ki:hasRole name="darklord">darklord<br/></ki:hasRole>
    <ki:hasRole name="goodguy">goodguy<br/></ki:hasRole>
    <ki:hasRole name="schwartz">schwartz<br/></ki:hasRole>
</p>

<h3>Roles you DON'T have</h3>

<p>
    <ki:lacksRole name="root">root<br/></ki:lacksRole>
    <ki:lacksRole name="president">president<br/></ki:lacksRole>
    <ki:lacksRole name="darklord">darklord<br/></ki:lacksRole>
    <ki:lacksRole name="goodguy">goodguy<br/></ki:lacksRole>
    <ki:lacksRole name="schwartz">schwartz<br/></ki:lacksRole>
</p>


</body>
</html>
