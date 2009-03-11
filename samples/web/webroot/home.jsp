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

<p>Hi <jsec:guest>Guest</jsec:guest><jsec:user><jsec:principal/></jsec:user>!
    ( <jsec:user><a href="<c:url value="/logout.jsp"/>">Log out</a></jsec:user>
    <jsec:guest><a href="<c:url value="/login.jsp"/>">Log in</a> (sample accounts provided)</jsec:guest> )
</p>

<p>Welcome to the Apache Ki Quickstart sample application.
    This page represents the home page of any web application.</p>

<jsec:user><p>Visit your <a href="<c:url value="/account"/>">account page</a>.</p></jsec:user>
<jsec:guest><p>If you want to access the user-only <a href="<c:url value="/account"/>">account page</a>,
    you will need to log-in first.</p></jsec:guest>

<h2>Roles</h2>

<p>To show some taglibs, here are the roles you have and don't have. Log out and log back in under different user
    accounts to see different roles.</p>

<h3>Roles you have</h3>

<p>
    <jsec:hasRole name="root">root<br/></jsec:hasRole>
    <jsec:hasRole name="president">president<br/></jsec:hasRole>
    <jsec:hasRole name="darklord">darklord<br/></jsec:hasRole>
    <jsec:hasRole name="goodguy">goodguy<br/></jsec:hasRole>
    <jsec:hasRole name="schwartz">schwartz<br/></jsec:hasRole>
</p>

<h3>Roles you DON'T have</h3>

<p>
    <jsec:lacksRole name="root">root<br/></jsec:lacksRole>
    <jsec:lacksRole name="president">president<br/></jsec:lacksRole>
    <jsec:lacksRole name="darklord">darklord<br/></jsec:lacksRole>
    <jsec:lacksRole name="goodguy">goodguy<br/></jsec:lacksRole>
    <jsec:lacksRole name="schwartz">schwartz<br/></jsec:lacksRole>
</p>


</body>
</html>
