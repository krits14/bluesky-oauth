import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import session from 'express-session';
import crypto from 'crypto';
import * as jose from 'jose';

const app = express();
const port = process.env.PORT || 3000;

//  Function to Generate a UUID (Fix for Older Node.js)
function generateUUID() {
    return crypto.randomBytes(16).toString('hex');
}

//  Store OAuth credentials securely
const BLUESKY_CLIENT_ID = process.env.CLIENT_ID || 'https://krits14.github.io/bluesky-oauth/client-metadata.json';
const BLUESKY_REDIRECT_URI = 'http://127.0.0.1:3000/callback';
const BLUESKY_AUTH_URL = "https://bsky.social/oauth/authorize";
const BLUESKY_TOKEN_URL = "https://bsky.social/oauth/token";

//  Generate Code Verifier & Challenge (PKCE)
const codeVerifier = crypto.randomBytes(32).toString('hex');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

//  Express session setup
app.use(session({
  secret: 'mySuperSecretKey',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

//  Function to Generate DPoP Proof (Now Handles Nonce Properly)
async function generateDPoPProof(tokenEndpoint, httpMethod, nonce = null) {
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');

    const jwtPayload = {
        jti: generateUUID(),
        htm: httpMethod,
        htu: tokenEndpoint,
        iat: Math.floor(Date.now() / 1000)
    };

    if (nonce) {
        jwtPayload.nonce = nonce; 
    }

    return await new jose.SignJWT(jwtPayload)
        .setProtectedHeader({
            alg: "RS256",
            typ: "dpop+jwt",
            jwk: await jose.exportJWK(publicKey)
        })
        .sign(privateKey);
}

//  Generate the OAuth Authorization URL
function getAuthorizationUrl() {
    return `${BLUESKY_AUTH_URL}?response_type=code&client_id=${encodeURIComponent(BLUESKY_CLIENT_ID)}&redirect_uri=${encodeURIComponent(BLUESKY_REDIRECT_URI)}&scope=atproto&code_challenge=${codeChallenge}&code_challenge_method=S256`;
}

//  Redirect user to Bluesky for authentication
app.get('/login', (req, res) => {
    const authorizationUrl = getAuthorizationUrl();
    console.log('Redirecting to:', authorizationUrl);
    res.redirect(authorizationUrl);
});

//  Handle OAuth Callback
app.get('/callback', async (req, res) => {
    const code = req.query.code;

    if (!code) {
        return res.status(400).send('Authorization code missing');
    }

    try {
        //  Step 1: Generate Initial DPoP Proof Without Nonce
        let dpopProof = await generateDPoPProof(BLUESKY_TOKEN_URL, "POST");

        //  Step 2: Try Exchanging Code for Access Token
        let tokenResponse;
        try {
            tokenResponse = await axios.post(BLUESKY_TOKEN_URL, {
                client_id: BLUESKY_CLIENT_ID,
                redirect_uri: BLUESKY_REDIRECT_URI,
                code: code,
                grant_type: 'authorization_code',
                code_verifier: codeVerifier,
            }, {
                headers: {
                    'DPoP': dpopProof,
                    'Content-Type': 'application/json',
                }
            });
        } catch (error) {
            //  Step 3: Extract DPoP Nonce from Error Response (If Exists)
            if (error.response && error.response.status === 400 && error.response.headers['dpop-nonce']) {
                console.log("🔄 Received DPoP nonce:", error.response.headers['dpop-nonce']);

                // Generate a new DPoP proof with the nonce
                const nonce = error.response.headers['dpop-nonce'];
                dpopProof = await generateDPoPProof(BLUESKY_TOKEN_URL, "POST", nonce);

                // Retry the token request with the nonce
                tokenResponse = await axios.post(BLUESKY_TOKEN_URL, {
                    client_id: BLUESKY_CLIENT_ID,
                    redirect_uri: BLUESKY_REDIRECT_URI,
                    code: code,
                    grant_type: 'authorization_code',
                    code_verifier: codeVerifier,
                }, {
                    headers: {
                        'DPoP': dpopProof,
                        'Content-Type': 'application/json',
                    }
                });
            } else {
                throw error; // If no nonce, throw original error
            }
        }

        //  Step 4: Store access token in session
        req.session.accessToken = tokenResponse.data.access_token;

        console.log(" Access Token Received:", tokenResponse.data);
        res.send(' Authentication successful! Access token stored.');
    } catch (error) {
        console.error(' Error exchanging code for token:', error.response?.data || error.message);
        res.status(500).send('OAuth process failed. Please check your credentials.');
    }
});

//  Secure API Request Using Token
app.get('/profile', async (req, res) => {
    if (!req.session.accessToken) {
        return res.status(401).send('Unauthorized. Please login first.');
    }

    try {
        const response = await axios.get('https://bsky.social/xrpc/com.atproto.identity.resolveHandle', {
            headers: { Authorization: `Bearer ${req.session.accessToken}` }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Error fetching profile:', error.response?.data || error.message);
        res.status(500).send('Failed to fetch profile.');
    }
});

//  Start the Express server
app.listen(port, () => {
    console.log(` Server running at http://127.0.0.1:${port}`);
});
