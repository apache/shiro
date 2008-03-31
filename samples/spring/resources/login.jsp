<%@ include file="include.jsp" %>

<html>

<head>
    <link type="text/css" rel="stylesheet" href="<c:url value="/jsecurity.css"/>"/>
</head>

<body onload="document.forms[0].elements[0].focus();">

<div id="contentBox">

    <h1>JSecurity Login</h1>

    <p>
        <span style="color: red;">
            <spring:bind path="command.*">
                ${status.errorMessage}
            </spring:bind>
        </span>
    </p>

    <form action="login" method="POST">
        Username: <input id="username" name="username" type="text"/><br/><br/>
        Password: <input name="password" type="password"/><br/><br/>
        <input type="submit" value="Login"/>
    </form>

    <p>Try logging in with username/passwords: user1/user1 and user2/user2.</p>
</div>
</body>

</html>