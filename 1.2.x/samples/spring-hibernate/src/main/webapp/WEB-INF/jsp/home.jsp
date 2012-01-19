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
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>

<html>
<head>
    <title>Apache Shiro Spring-Hibernate Sample Application</title>
    <link rel="stylesheet" type="text/css" href="<c:url value="/styles/sample.css"/>"/>
</head>
<body>

<div id="bigbox">
    <div class="title clearfix"><div style="float: left">Apache Shiro Sample App - Home</div><div class="info" >Logged in as ${currentUser.username} (<a href="<c:url value="/s/logout"/>">Logout</a>)</div></div>


    <div class="content">

        <p>Users in the system:</p>
        <ul>
            <c:forEach var="user" items="${users}">
                <li>${user.username} - ${user.email}</li>
            </c:forEach>
        </ul>

        <p>
        <shiro:hasPermission name="user:manage">
            Since you are logged in as the admin user, you can <a href="<c:url value="/s/manageUsers"/>">manage site users</a>.
        </shiro:hasPermission>
        <shiro:lacksPermission name="user:manage">
            Since you are not logged in as the admin user, you can't manage site users.
        </shiro:lacksPermission>
        </p>
    </div>

</div>

</body>
</html>
