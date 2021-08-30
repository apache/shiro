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

<!DOCTYPE html>
<html lang="en">

<head>
	<title>Webapp sample login page</title>
    <link type="text/css" rel="stylesheet" href="<c:url value="/style.css"/>"/>
</head>
<body>

<h2>Please Log in</h2>

<shiro:guest>
    <p>Here are a few sample accounts to play with in the default text-based Realm (used for this
        demo and test installs only). Do you remember the movie these names came from? ;)</p>


    <style type="text/css">
        table.sample {
            border-width: 1px;
            border-style: outset;
            border-color: blue;
            border-collapse: separate;
            background-color: rgb(255, 255, 240);
        }

        table.sample th {
            border-width: 1px;
            padding: 1px;
            border-style: none;
            border-color: blue;
            background-color: rgb(255, 255, 240);
        }

        table.sample td {
            border-width: 1px;
            padding: 1px;
            border-style: none;
            border-color: blue;
            background-color: rgb(255, 255, 240);
        }
    </style>


    <table class="sample" style="padding: 10px;">
    	<caption style="padding: 10px;"> Sample accounts </caption>
        <thead>
        <tr>
            <th id="username">Username</th>
            <th id="password">Password</th>
        </tr>
        </thead>
        <tbody>
        <tr>
            <td>root</td>
            <td>secret</td>
        </tr>
        <tr>
            <td>presidentskroob</td>
            <td>12345</td>
        </tr>
        <tr>
            <td>darkhelmet</td>
            <td>ludicrousspeed</td>
        </tr>
        <tr>
            <td>lonestarr</td>
            <td>vespa</td>
        </tr>
        </tbody>
    </table>
    <br/><br/>
</shiro:guest>

<form name="loginform" action="" method="post">
    <table style="text-align:left; padding: 10px;">
    	<caption> Log in </caption>
        <tr>
            <td><input type="text" name="username" maxlength="30" placeholder="Username"></td>
        </tr>
        <tr>
            <td><input type="password" name="password" maxlength="30" placeholder="Password"></td>
        </tr>
        <tr>
            <td colspan="2" style="text-align:left; font-size:12px;"><input type="checkbox" name="rememberMe"> Remember me</td>
        </tr>
        <tr>
            <td colspan="2" style="text-align:right;"><input type="submit" name="submit" value="Login"></td>
        </tr>
    </table>
</form>

</body>
</html>
