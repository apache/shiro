<%@ include file="include.jsp" %>

<html>
<body>
<p>You have successfully logged in.</p>

<p>
    <jsecurity:hasRole name="role1">You have role 1.</jsecurity:hasRole>
    <jsecurity:lacksRole name="role1">You do not have role 1.</jsecurity:lacksRole>
    <jsecurity:hasRole name="role2">You have role 2.</jsecurity:hasRole>
    <jsecurity:lacksRole name="role2">You do not have role 2.</jsecurity:lacksRole>
</p>

<p>
    <form action="<c:url value="/secure/index"/>" method="POST">
        Enter value here to store in session: <input type="text" name="value" value="${command.value}" size="30"/>
        <input type="submit" value="Save"/>
        <button type="button" onclick="document.location.href='<c:url value="/secure/index"/>';">Refresh</button>
    </form>

</p>

<p>Click <a href="<c:url value="/gateway/jsecurity.jnlp?sessionId=${sessionId}"/>">here</a> to launch webstart application.</p>

<p>Click <a href="<c:url value="/gateway/logout"/>>here</a> to logout.</p>
</body>
</html>