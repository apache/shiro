<%@ include file="include.jsp"%>

<html>

<body onload="javascript:document.forms[0].elements[0].focus();">
    <h3>Login</h3>

    <p>
    <span style="color: red;">
        <spring:bind path="command.*">
            ${status.errorMessage}
        </spring:bind>
    </span>
    </p>

    <form action="login" method="POST">
        Username: <input id="username" name="username" type="text"/><br/>
        Password: <input name="password" type="password"/><br/><br/>
        <input type="submit" value="Login"/>
    </form>

    <p>Try logging in with username/passwords: user1/user1 and user2/user2.</p>

</body>

</html>