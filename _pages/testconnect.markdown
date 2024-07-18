---
title:  "testconnect"
layout: single
type: pages
permalink: /test-connect/
---

<html>
<head>
    <title>CSRF Token Demo</title>
</head>
<body>
    <h1>CSRF Token Demonstration</h1>
    <form id="demoForm">
        <input type="hidden" id="csrf_token" name="csrf_token">
        <label for="name">Name:</label>
        <input type="text" id="name" name="name">
        <button type="submit">Submit</button>
    </form>

    <div id="result"></div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Fetch the CSRF token from the server
            fetch('https://files.thecybersanctuary.com/generate_csrf_token.php')
                .then(response => response.text())
                .then(token => {
                    document.getElementById('csrf_token').value = token;
                });

            // Handle form submission
            document.getElementById('demoForm').addEventListener('submit', function(event) {
                event.preventDefault();

                var formData = new FormData(this);

                fetch('https://files.thecybersanctuary.com/validate_csrf_token.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.text())
                .then(result => {
                    document.getElementById('result').innerText = result;
                });
            });
        });
    </script>
</body>
</html>

