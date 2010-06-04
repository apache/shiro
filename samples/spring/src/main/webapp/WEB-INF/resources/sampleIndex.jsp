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
    <link type="text/css" rel="stylesheet" href="<c:url value="/shiro.css"/>"/>
</head>

<body>

<div id="contentBox">
    <img src="<c:url value="/logo.png"/>" style="margin-top:20px; border:0"/><br/>

    <h2>You have successfully logged in as <shiro:principal/>.</h2>

    Session ID: ${subjectSession.id}

    <h3>Session Attribute Keys</h3>
    <table border="1">
        <tr>
            <th>Key</th>
            <th>Value</th>
        </tr>
        <c:forEach items="${sessionAttributes}" var="entry">
            <tr>
                <td>${entry.key}</td>
                <td>${entry.value}</td>
            </tr>
        </c:forEach>
    </table>

    <p style="font-weight: bold;">
        <shiro:hasRole name="role1">You have role 1.<br/></shiro:hasRole>
        <shiro:lacksRole name="role1">You do not have role 1.<br/></shiro:lacksRole>
        <shiro:hasRole name="role2">You have role 2.<br/></shiro:hasRole>
        <shiro:lacksRole name="role2">You do not have role 2.<br/></shiro:lacksRole>
    </p>

    <p style="font-weight: bold;">
        <shiro:hasPermission name="permission1">You have permission 1.<br/></shiro:hasPermission>
        <shiro:lacksPermission name="permission1">You do not have permission 1.<br/></shiro:lacksPermission>
        <shiro:hasPermission name="permission2">You have permission 2.<br/></shiro:hasPermission>
        <shiro:lacksPermission name="permission2">You do not have permission 2.<br/></shiro:lacksPermission>
    </p>


    <form action="<c:url value="/s/index"/>" method="POST">
        Enter value here to store in session: <input type="text" name="value" value="${command.value}" size="30"/>
        <input type="submit" value="Save"/>
        <button type="button" onclick="document.location.href='<c:url value="/s/index"/>';">Refresh</button>
    </form>


    <p>
        Click <a href="<c:url value="/s/shiro.jnlp?sessionId=${subjectSession.id}"/>">here</a> to launch webstart
        application. (Need to be running <span style="font-weight:bold">mvn jetty:run-exploded</span> to have webstart
        app
        resources available through the webapp context)
    </p>


    <p>
        Click <a href="<c:url value="/s/logout"/>">here</a> to logout.
    </p>
</div>
</body>
</html>