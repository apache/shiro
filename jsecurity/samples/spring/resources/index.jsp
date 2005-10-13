<%@ include file="include.jsp" %>

<html>
<body>
<p>You have successfully logged in.</p>

<p>
    <c:if test="${hasRole1}">You have role 1.<br/></c:if>
    <c:if test="${!hasRole1}">You do not have role 1.<br/></c:if>
    <c:if test="${hasRole2}">You have role 2.<br/></c:if>
    <c:if test="${!hasRole2}">You do not have role 2.<br/></c:if>
</p>

<p>Click <a href="/jsecurity-spring/gateway/logout">here</a> to logout.</p>
</body>
</html>