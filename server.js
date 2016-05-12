var fs          = require('fs'); 
var https       = require('https');
var http        = require('http');
var yub         = require('yub');
var express     = require('express');
var session     = require('express-session');
var bodyParser = require('body-parser')

//
// Yubikey server configuration

var yubikeyConf = JSON.parse(fs.readFileSync("yubikey-conf.json", "utf8"));
yub.init(yubikeyConf.clientId, yubikeyConf.secret);


//
// Application configuration

var app = express();
app.use(session({
    secret: "no one is innocent",
    resave: false,
    saveUninitialized: false
}));
app.use(express.static('public'));
app.use(bodyParser.json())

var user2keyId = {};

//
// Handlers

    //
    // Request logging

    app.all('*', function(req, res, next) {
        var s = new Date()+' '+ 
            req.connection.remoteAddress+' '+ 
            req.socket.getPeerCertificate().subject.CN+' '+ 
            req.method+' '+req.url
        console.log(s);    
        next(); 
    });

    //
    // Authentication

    app.all('/auth', function(req, res) {
        
        function authCompleted() {
            res.send("Authentication successfully completed")
        }

        function authFailed(cause) {
            res.sendStatus(401);
        }

        var token = req.body.otp;
        var user = req.socket.getPeerCertificate().subject.CN;
        
        if (token) {
        
            //
            // Verifies the keys and the token
            
            yub.verify(token, function(err,data) {
            
                console.log("Data: " + JSON.stringify(data,null,3));
                
                if (data.valid) {
                    
                    var keyId = data.identity;
                    var existingKeyId = user2keyId[user];

                    if (existingKeyId === undefined) {

                        user2keyId[user] = keyId;
                        req.session.authenticated = true;
                        authCompleted();

                    } else if (existingKeyId === keyId) {

                        req.session.authenticated = true;
                        authCompleted();
                        
                    } else {

                        authFailed("Invalid key id for user " + user);
                    }

                } else {
                    authFailed(data.status);
                }
            });
        } else {

            authFailed("Missing token");
        }
    });

    //
    // Authentication filter

    app.all('/*', function(req,res,next) {
        if (req.session.authenticated) {
            next();
        } else {
            res.statusCode = 401;
            res.end('Unauthorized');
        }
    });

    //
    // Ping

    app.post('/ping', function(req, res) {
        res.json({
            status: "OK"
        });
    });

//
// HTTPS server configuration 
 
var options = { 
    key: fs.readFileSync('server-key.pem'), 
    cert: fs.readFileSync('server-crt.pem'), 
    ca: fs.readFileSync('ca-crt.pem'), 
    requestCert: true,
    rejectUnauthorized: true
}; 

https.createServer(options, app).listen(8443);
