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
    <div class="title clearfix"><div style="float: left">Apache Shiro Sample App - Manage Users</div><div class="info" >Logged in as ${currentUser.username} (<a href="<c:url value="/s/logout"/>">Logout</a>)</div></div>


    <div class="content">

        <table id="manageUsers">
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Actions</th>
            </tr>
            <c:forEach var="user" items="${users}">
            <tr>
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td><a href="<c:url value="/s/editUser?userId=${user.id}"/>">Edit</a><c:if test="${user.id ne 1}">&nbsp;|&nbsp;<a href="<c:url value="/s/deleteUser?userId=${user.id}"/>">Delete</a></c:if>
                </td>
            </tr>
            </c:forEach>
        </table>

        <p>Return to <a href="<c:url value="/s/home"/>">Home</a></p>
    </div>

</div>

</body>
</html>
