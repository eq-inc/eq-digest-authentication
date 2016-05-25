# eq-digest-authentication
Digest authentication module for Eq applications.

## Example

```JavaScript
const express = require('express'),
    digest_authentication = require('eq-digest-authentication'),
    digest_authentication_strategy = require('eq-digest-authentication-strategy'),
    users = [
        {username: 'username1', password: 'password1'},
        {username: 'username2', password: 'password2'}
    ],
    options = {
        realm: 'realm',
        qop: 'auth',
        algorithm: 'sha-256'
    },
    app = express(),
    strategy = digest_authentication_strategy.object(users, options),
    digest_authentication = digest_authentication(strategy, options);

app.use(digest_authentication.middleware());
```
