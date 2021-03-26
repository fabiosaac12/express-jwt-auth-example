require('dotenv').config(); // to use environment variables from the .env file

const express = require('express');
const jwt = require('jsonwebtoken');

const generateAccessToken = user => jwt.sign(
    user, 
    process.env.ACCESS_TOKEN_SECRET, 
    { expiresIn: '15s' }
);

const generateRefreshToken = user => jwt.sign(
    user, 
    process.env.ACCESS_TOKEN_SECRET
);

// authenticate token middleware, for the protected routes
const authenticateToken = ( req, res, next ) => {
    const token = req.headers['authorization']?.split(' ')[1]; // the access token should come as "Bearer <token>"
    if ( !token ) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, ( err, user ) => {
	if ( err ) return res.sendStatus(403);
	req.user = user;
	next();
    });
}

const app = express();
app.use( express.json() );

// only for the example; maybe you want to stock the refresh tokens in some database
let refreshTokens = [];

/* this route will use the middleware authenticateToken to verify if the 
access token is valid and, in true case, return the requested data */
app.get('/protected', authenticateToken, ( req, res ) => {
    return res.json({ data: {} });
})

app.post('/refreshToken', ( req, res ) => {
    const refreshToken = req.body.refreshToken;
    if ( !refreshToken ) return res.sendStatus(401);
    if ( !refreshTokens.includes( refreshToken ) ) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.ACCESS_TOKEN_SECRET, ( err, user ) => {
	if ( err ) return res.sendStatus(403);

	// generate a new access token for the user if the refresh token is valid
	const newAccessToken = generateAccessToken({ username: user.username });

	res.json({ accessToken: newAccessToken });
    })
})

// only for the example; maybe you need to verify the user with some database
const verifyUser = user => user === user && true;

app.post('/login', ( req, res ) => {
    const user = req.body; //should be an object with the user authentication data
    if ( verifyUser( user ) ) {
	const accessToken = generateAccessToken( user );
	const refreshToken = generateRefreshToken( user );
	
	/* add the refresh token to the refresh token list, so that the 
	refresh token will be able to be used to generate new access tokens */
	refreshTokens.push( refreshToken );

	return res.json({ accessToken, refreshToken });
    }
    res.sendStatus(401)
})

app.delete('/logout', (req, res) => {
    const refreshToken = req.body.refreshToken;

    /* remove the refresh token from the refres tokens list, 
    so that the token can no loger be used to generate more access tokens */
    refreshTokens = refreshTokens.filter( t => t !== refreshToken );

    res.sendStatus(204)
})

app.listen(4000, () => console.log('auth server in port 4000'))
