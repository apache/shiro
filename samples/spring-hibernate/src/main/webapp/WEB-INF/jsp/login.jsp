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
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<html>
<head>
    <title>Apache Shiro Spring-Hibernate Sample Application</title>
    <link rel="stylesheet" type="text/css" href="<c:url value="/styles/sample.css"/>"/> 
</head>
<body>
    <div id="box">
        <div class="title">Apache Shiro Sample App - Login</div>

        <div class="content">
            <form:form modelAttribute="loginCommand">

                <form:errors path="*" element="div" cssClass="errors"/>

                <div><div class="form-label">Username:</div><form:input path="username"/></div>
                <div><div class="form-label">Password:</div><form:password path="password"/></div>
                <div><form:checkbox path="rememberMe"/> Remember Me</div>
                <div><input type="submit" value="Login"/></div>
            </form:form>

            <div>Don't have an account? <a href="<c:url value="/s/signup"/>">Sign up</a></div>
        </div>
    </div>

    <p>
        Users created through the signup form have the role "user".  You can also log in as admin/admin, which has the
        "admin" role.
    </p>

    <script type="text/javascript">
        document.getElementById('username').focus();
    </script>

</body>
</html>
