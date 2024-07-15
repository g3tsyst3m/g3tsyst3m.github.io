---
title:  "Login"
layout: single
type: pages
permalink: /login-prompt/
---

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Form with AJAX</title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
</head>
<body>
    <h2>Login Form</h2>
    <form id="loginForm">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        
        <input type="submit" value="Login">
    </form>
    <div id="result"></div>

    <script>
        $(document).ready(function() {
            $('#loginForm').submit(function(e) {
                e.preventDefault(); // Prevent form submission
                var username = $('#username').val();
                var password = $('#password').val();

                // AJAX request
                $.ajax({
                    type: 'POST',
                    url: 'https://files.thecybersanctuary.com/authenticate.php', // PHP script for authentication
                    data: {
                        username: username,
                        password: password
                    },
                    success: function(response) {
                        // Update result div with the server response
                        $('#result').html(response);
						if (response.includes("Successfully authenticated")) {
                            // Store username in local storage
                            localStorage.setItem('username', username);
                    }
                });
            });
        });
    </script>
</body>
</html>
