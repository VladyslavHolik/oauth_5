const express = require('express')
const bodyParser = require('body-parser')
const path = require('path')
const jwt = require('jsonwebtoken')
const secrets = require("./my_application_secrets.json")
const request = require('sync-request')
const {auth} = require("express-oauth2-jwt-bearer")

const PORT = 3000
const BEARER_HEADER = 'Authorization'
const REFRESH_HEADER = 'Refresh'
const BLOCK_TIME_IN_MILLIS = 60 * 1000

const loginHistory = {}
let publicKey

const app = express()
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

// Filter
app.use((req, res, next) => {
    let token
    if (req.get(BEARER_HEADER)) {
        token = req.get(BEARER_HEADER).split(" ")[1]
    }

    if (req.get(REFRESH_HEADER)) {
        req.refresh = req.get(REFRESH_HEADER)
    }

    if (token) {
        let payload = verify(token)
        req.token = token

        if (payload !== undefined && payload !== null) {
            req.payload = payload
        }
    }
    next()
})

// Get mapping "/"
app.get('/', (req, res) => {
    if (req.payload) {
        return res.json(getUserData(req.payload.sub, req.token))
    } else if (req.token) {
        return res.status(403).send()
    }
    res.sendFile(path.join(__dirname + '/index.html'))
})

// Get mapping "/signup"
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname + '/signup.html'));
})

// Post mapping "/api/signup"
app.post('/api/signup', (req, res) => {
    const {login, password, name, nickname} = req.body;

    const accessToken = getOauthToken()
    const response = registerUser(accessToken, login, name, nickname, password)

    if (response.statusCode === 201) {
        console.log(`Successfully registered user with login ${login}`);
        return res.json({redirect: '/'});
    }

    return res.status(500).send();
})

// Post mapping "/api/login"
app.post('/api/login', (req, res) => {
    const userAddress = req.socket.remoteAddress;
    updateUserStatus(userAddress)

    if (isUserBlocked(userAddress)) {
        console.log(`Unsuccessful attempt to login from address ${userAddress}`)
        increaseUnsuccessfulAttempts(userAddress)
        res.status(401).send()
    }
    const {username, password} = req.body

    const authResponse = authenticateUser(username, password)
    if (authResponse) {
        return res.json(JSON.parse(authResponse.getBody()))
    }

    console.log(`Unsuccessful attempt to login from address ${userAddress}`)
    increaseUnsuccessfulAttempts(userAddress)
    res.status(401).send()
})

const verifyMiddleware = auth({
    audience: secrets.audience,
    issuerBaseURL: `https://${secrets.domain}`,
})

// Get mapping "/api/info"
app.get('/api/info', verifyMiddleware, function (req, res) {
    if (req.token) {
        return res.json(getUserData(req.payload.sub, req.token))
    }
})

// Get mapping "/api/refresh"
app.get('/api/refresh', (req, res) => {
    if (req.refresh) {
        return res.json(getAccessToken(req.refresh))
    }
    res.status(403).send()
})

// Starting listening
app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})

function getOauthToken() {
    const response = request('POST', `${secrets.issuer}oauth/token`,
        {
            headers: {
                'content-type': 'application/x-www-form-urlencoded'
            },
            body: `grant_type=client_credentials&client_id=${secrets.clientId}&client_secret=${secrets.clientSecret}&audience=${secrets.audience}`
        })

    return JSON.parse(response.getBody('utf8')).access_token
}

function registerUser(accessToken, login, name, nickname, password) {
    return request('POST', `${secrets.issuer}api/v2/users`,
        {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            },
            json: {
                email: login,
                name: name,
                connection: 'Username-Password-Authentication',
                password: password,
                nickname: nickname
            }
        })
}

function authenticateUser(username, password) {
    return request('POST', `${secrets.issuer}oauth/token`,
        {
            headers: {
                'content-type': 'application/x-www-form-urlencoded'
            },
            body: `grant_type=http://auth0.com/oauth/grant-type/password-realm&client_id=${secrets.clientId}&client_secret=${secrets.clientSecret}&audience=${secrets.audience}&username=${username}&password=${password}&scope=offline_access&realm=Username-Password-Authentication`
        })
}

function getUserData(userId, user_access_token) {
    const response = request('GET', `${secrets.issuer}api/v2/users/${userId}`,
        {
            headers: {'Authorization': `Bearer ${user_access_token}`}
        })

    return JSON.parse(response.getBody('utf8'));
}

function getAccessToken(refreshToken) {
    const response = request('POST', `${secrets.issuer}oauth/token`,
        {
            headers: {
                'content-type': 'application/x-www-form-urlencoded'
            },
            body: `grant_type=refresh_token&client_id=${secrets.clientId}&client_secret=${secrets.clientSecret}&refresh_token=${refreshToken}`
        })

    return JSON.parse(response.getBody('utf8'))
}

function isUserBlocked(userAddress) {
    return userAddress in loginHistory && loginHistory[userAddress].status === 'Blocked'
}

function updateUserStatus(userAddress) {
    let userHistory = loginHistory[userAddress]
    if (userAddress in loginHistory && userHistory.status === 'Blocked' && userHistory.blockedUntil < new Date()) {
        userHistory.status = 'Allowed'
        userHistory.unsuccessfulAttempts = 0
        userHistory.blockedUntil = null
    }
}

function increaseUnsuccessfulAttempts(userAddress) {
    if (!(userAddress in loginHistory)) {
        loginHistory[userAddress] = {status: 'Allowed', unsuccessfulAttempts: 1};
    } else {
        loginHistory[userAddress].unsuccessfulAttempts += 1;
    }

    if (loginHistory[userAddress].unsuccessfulAttempts > 3) {
        loginHistory[userAddress].status = 'Blocked'
        loginHistory[userAddress].blockedUntil = new Date(new Date().getTime() + BLOCK_TIME_IN_MILLIS)
        console.log(`User with address ${userAddress} is blocked until ${loginHistory[userAddress].blockedUntil}`)
    }
}

function getPayload(token) {
    return jwt.decode(token);
}

function getPublicKey() {
    if (publicKey === null || publicKey === undefined) {
        const response = request('GET', `${secrets.issuer}pem`)
        publicKey = response.getBody('utf8')
    }
    return publicKey
}

function verify(token) {
    const publicKey = getPublicKey()
    const verifyOptions = {
        issuer: `https://${secrets.domain}/`,
        audience: secrets.audience,
        algorithms: ['RS256'],
    }
    return jwt.verify(token, publicKey, verifyOptions)
}
