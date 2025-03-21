// return;
require('dotenv').config();

// blockedips.json is not a database.
const BlockedIPs = require("./blockedips.json"); // if you are cloning this, make sure to make this file

// TODO: Despaghettify this.

const fs = require("fs");
const jimp = require("jimp");
const JSZip = require("jszip");
const Database = require("easy-json-database");
const Cast = require("./classes/Cast.js");

const DEBUG_logAllFailedData = Cast.toBoolean(process.env.LogFailedData);

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const app = express();
const port = 8080;
const fetch = require("node-fetch");

const Filter = require('bad-words');
let globalOperationCounter = 0;
let warnings = 0;

const { encrypt, decrypt } = require("./utilities/encrypt.js");
const log = require("./utilities/log.js");

const UserManager = require("./classes/UserManager.js");
//const UserStorage = require("./classes/UserStorage.js");
//const StorageSpace = new UserStorage(32000000, 3); // 32 mb per data piece, 3 keys per container
UserManager.load(); // should prevent logouts

const ProjectList = require("./classes/ProjectList.js");
const GenericList = require("./classes/GenericList.js");
const ReportList = require("./classes/ReportList.js");

const AdminAccountUsernames = new Database(`${__dirname}/data/admins.json`);
const ApproverUsernames = new Database(`${__dirname}/data/approvers.json`);

const GlobalRuntimeConfig = new Database(`${__dirname}/data/globalsettings.json`);

// UserManager.setCode('debug', 'your-mom');
let Profanity = [];

app.use(express.json({ limit: process.env.ServerSize ?? '50mb' })); // Adjust the limit as needed
app.use(express.urlencoded({
    limit: process.env.ServerSize ?? '50mb', 
    extended: false
})); // Adjust the limit
function DecryptArray(array) {
    const na = [];
    for (const value of array) {
        const decrypted = decrypt(value);
        na.push(decrypted);
    }
    return na;
}
function EncryptArray(array) {
    const na = [];
    for (const value of array) {
        const encrypted = encrypt(value);
        na.push(encrypted);
    }
    return na;
}
app.use((req, res, next) => {
    // Allow requests from both 'https://snail-ide.vercel.app' and 'https://snail-ide.js.org,' this also allows our test frontend
    res.header('Access-Control-Allow-Origin', 'https://snail-ide.vercel.app/', 'https://snailshare.vercel.app/', 'https://snail-ide.js.org', 'https://test-henna-alpha-94.vercel.app/', 'https://snail-ide.com', 'https://editor.snail-ide.com');
    // You can also use '*' to allow any origin, but this is less secure
    // res.header('Access-Control-Allow-Origin', '*');
    next();
});

function SafeJSONParse(json) {
    try {
        return JSON.parse(json);
    } catch {
        return {};
    }
}

const inList = require("./illegalwords.js");

const CheckForIllegalWording = (...args) => {
    for (const argument of args) {
        for (const illegalWord of inList) {
            const checking = Cast.toString(argument)
                .toLowerCase()
                .replace(/[ _\-!?.#/\\,'"@$%^&*\(\)]+/gmi, '');
            if (checking.includes(illegalWord)) {
                return true;
            }
        }
    }
    return false;
};

// Example usage:
const containsIllegalWord = CheckForIllegalWording("Some text with word2", "Another text without illegal words");
console.log(containsIllegalWord); // Output: true or false based on whether any illegal word is found



function Deprecation(res, reason = "") { // if an endpoint is deprecated, use this.
    res.status(400);
    res.header("Content-Type", 'application/json');
    res.json({
        error: "Deprecated Endpoint",
        reason
    });
}
function escapeXML(unsafe) {
    if (typeof unsafe !== 'string') {
        if (unsafe) {
            // This happens when we have hacked blocks from 2.0
            // See #1030
            unsafe = String(unsafe);
        } else {
            console.error(`Unexptected type ${typeof unsafe} in xmlEscape at: ${new Error().stack}`)
            return unsafe;
        }
    }
    return unsafe.replace(/[<>&'"\n]/g, c => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            case '\n': return '&#10;'
        }
    });
};

/**
 * Returns either a JSZip instance or null.
 * @param {Buffer} buffer 
 * @param {JSZip.JSZipLoadOptions} options 
 * @returns {Promise<JSZip?>}
 */
const safeZipParse = (buffer, options) => {
    return new Promise((resolve) => {
        if (!buffer) return resolve();
        JSZip.loadAsync(buffer, options).then(zip => {
            resolve(zip);
        }).catch(() => {
            resolve();
        });
    });
};

// illegalextensions.json is not a database.
const illegalExtensionsList = require("./illegalextensions.json");
const checkExtensionIsAllowed = (extension, isUrl) => {
    if (!extension) return true;
    let propertyName = "id";
    if (isUrl) {
        propertyName = "url";
    }
    const extensionsConfig = illegalExtensionsList[propertyName];
    const isIncluded = extensionsConfig.items.includes(extension);
    const isBlacklist = extensionsConfig.useAsWhitelist !== true;
    if (isBlacklist && isIncluded) {
        return false;
    }
    if (!isBlacklist && isIncluded) {
        return true;
    }
    if (!isBlacklist && !isIncluded) {
        return false;
    }
    return true; // isBlacklist and isntIncluded
};

app.use(cors({
    origin: '*',
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}));
app.use((req, res, next) => {
    if (BlockedIPs.includes(req.ip)) return res.sendStatus(403);
    console.log(`${req.ip}: ${req.originalUrl}`);
    next();
});
app.set('trust proxy', 1);
app.use(rateLimit({
    validate: {
        trustProxy: true,
        xForwardedForHeader: true,
    },
    windowMs: 5000,  // 150 requests per 5 seconds
    limit: 150,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
}));

const errorHandler = (err, req, res, next) => {
    // Allow requests from both 'https://snail-ide.vercel.app' and 'https://snail-ide.js.org,' this also allows our test frontend
    const origin = req.header('Origin');
    switch (origin) {
        case 'https://snail-ide.vercel.app':
        case 'https://snail-ide.js.org':
        case 'https://test-henna-alpha-94.vercel.app':
        case 'https://snail-ide.com':
        case 'https://snailshare.vercel.app/':
        // case 'http://localhost:5173':
        case 'https://editor.snail-ide.com':
            res.set('Access-Control-Allow-Origin', origin);
            break;
        default:
            break;
    }
    // You can also use '*' to allow any origin, but this is less secure
    // res.header('Access-Control-Allow-Origin', '*');
    log('error', err.stack);
    console.error(err.stack);
    if (err.name === 'PayloadTooLargeError') return res.status(413).json({ "error": "RequestTooLarge" });
    return res.status(500).json({ "error": "Report" });
};

app.use(errorHandler);

app.get('/', async function (_, res) { // just basic stuff. returns the home page
    res.redirect('https://snail-ide.vercel.app/');
});
app.get('/robots.txt', async function (_, res) { // more basic stuff!!!!! returns robots.txt
    res.sendFile(path.join(__dirname, './robots.txt'));
});

// get API metadata
app.get('/api', async function (_, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.sendFile(path.join(__dirname, './metadata.json'));
});
// PING COMMAND TO CHECK IF API IS WORKING (LOL)
app.get('/api/ping', async function (_, res) {
    res.send("Pong!")
});
// Error?
app.get('/api/warnings', async function (_, res) {
    res.json({warnings: warnings});
});
const projectTemplate = fs.readFileSync('./project.html').toString();
app.get('/:id', async function (req, res) {
    const db = new Database(`${__dirname}/data/projects/published.json`);
    const json = db.get(String(req.params.id));
    if (!json) {
        res.sendFile(path.join(__dirname, './404-noproject.html'));
        return;
    }
    res.status(200);
    let html = projectTemplate
    for (const prop in json) {
        html = html.replaceAll(`{project.${prop}}`, escapeXML(json[prop]));
    }
    res.send(html);
});

// profile stuff
const GenerateProfileJSON = (username) => {
    const rawBadges = UserManager.getProperty(username, "badges");
    const badges = Array.isArray(rawBadges) ? rawBadges : [];
    const isDonator = badges.includes('donator');
    const isCool = badges.includes('cool_award')

    let rank = UserManager.getProperty(username, "rank");
    if (typeof rank !== "number") rank = 0;
    const signInDate = UserManager.getProperty(username, "firstLogin") || Date.now();
    const projectsDatabase = new Database(`${__dirname}/data/projects/published.json`);
    const userProjects = projectsDatabase.all()
        .map(value => { return value.data })
        .filter(project => (project.owner === username));
    const canRequestRankUp = (userProjects.length > 3 // if we have 3 projects and
        && (Date.now() - signInDate) >= 4.32e+8) // first signed in 5 days ago
        || badges.length > 0; // or we have a badge

    const followers = UserManager.getFollowers(username);

    return {
        username,
        admin: AdminAccountUsernames.get(username),
        approver: ApproverUsernames.get(username),
        banned: UserManager.isBanned(username), // skipped in /profile but provided in /usernameFromCode
        badges,
        donator: isDonator,
        cool: isCool,
        rank,
        followers: followers.length,
        followersList: followers.length !== 0 ? followers : 'none',
        canrankup: canRequestRankUp && rank === 0,
        viewable: userProjects.length > 0,
        projects: userProjects.length // we check projects anyways so might aswell
    };
};
app.get('/api/users/profile', async function (req, res) { // check if user is banned
    const username = Cast.toString(req.query.username);
    if (typeof username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NoUserSpecified" });
        return;
    }
    if (UserManager.isBanned(username)) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(GenerateProfileJSON(username));
});
app.post('/api/users/requestRankUp', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const username = Cast.toString(packet.username);
    const rawBadges = UserManager.getProperty(username, "badges");
    const badges = Array.isArray(rawBadges) ? rawBadges : [];

    let rank = UserManager.getProperty(username, "rank");
    if (typeof rank !== "number") rank = 0;
    if (rank !== 0) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "AlreadyRankedHighest" });
        return;
    }
    const signInDate = UserManager.getProperty(username, "firstLogin") || Date.now();
    const projectsDatabase = new Database(`${__dirname}/data/projects/published.json`);
    const userProjects = projectsDatabase.all()
        .map(value => { return value.data })
        .filter(project => (project.owner === username));
    const canRequestRankUp = (userProjects.length > 3 // if we have 3 projects and
        && (Date.now() - signInDate) >= 4.32e+8) // first signed in 5 days ago
        || badges.length > 0; // or we have a badge
    if (!canRequestRankUp) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Ineligble" });
        return;
    }
    UserManager.setProperty(username, "rank", 1);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// security stuff i guess :idk_man:
app.get('/api/users/isBanned', async function (req, res) { // check if user is banned
    if (typeof req.query.username != "string") {
        res.status(400)
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidRequest" })
        return
    }
    res.status(200)
    res.header("Content-Type", 'application/json');
    res.json({ "banned": UserManager.isBanned(req.query.username) })
});
app.get('/api/users/assignPossition', async function (req, res) { // give someone admin or approver (only admins can use this)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        log('assignPosition', `${packet.user} tried to assign a position to ${packet.target} but they were not authorized to assign them.`)
        return;
    }
    AdminAccountUsernames.set(packet.target, Cast.toBoolean(packet.admin));
    ApproverUsernames.set(packet.target, Cast.toBoolean(packet.approver));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": 'AppliedStatus' });
});
app.get('/api/errorAllProjectRequests', async function (req, res) { // set the state of allowing or preventing all project info getting requests (only admins can use this)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    GlobalRuntimeConfig.set("allowGetProjects", Cast.toBoolean(packet.enabled));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": 'AppliedStatus' });
});
// get approved projects
app.get('/api/projects/getApproved', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForEveryone" });
        return;
    }

    const db = new Database(`${__dirname}/data/projects/published.json`);
    // this is explained in paged api but basically just add normal projects to featured projects
    // because otherwise featured projects would come after normal projects
    const featuredProjects = [];
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted === true).filter(project => {
        if (project.featured) {
            featuredProjects.push(project);
        }
        return project.featured != true;
    });
    let returnArray = featuredProjects.concat(projects);
    if (Cast.toBoolean(req.query.reverse)) {
        returnArray = structuredClone(returnArray).reverse();
    }
    // make project list
    // new ProjectList() with .toJSON will automatically cut the pages for us
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
// get approved projects but only a certain amount
app.get('/api/projects/max', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForEveryone" });
        return;
    }

    function grabArray() {
        const db = new Database(`${__dirname}/data/projects/published.json`)
        // this is explained in paged api but basically just add normal projects to featured projects
        // because otherwise featured projects would come after normal projects
        const featuredProjects = [];
        const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
            return sproject.date - project.date;
        }).filter(proj => proj.accepted === true).filter(project => {
            if (project.featured) {
                featuredProjects.push(project);
            }
            return project.featured != true;
        })
        if (String(req.query.featured) == "true") {
            return featuredProjects;
        }
        if (String(req.query.hidefeatured) == "true") {
            return projects;
        }
        const returnArray = featuredProjects.concat(projects);
        return returnArray;
    }
    let count = Number(req.query.amount);
    if (isNaN(count)) count = 0;
    if (!isFinite(count)) count = 0;
    if (count < 0) count = 0;
    if (count > 20) count = 20;
    count = Math.round(count);
    const arr = grabArray().slice(0, count);
    const projectsList = new ProjectList(arr);
    const returning = projectsList.toArray(false);
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
// get unapproved projects
app.get('/api/projects/getUnapproved', async function (req, res) {
    // 6/3/2023 unapproved projects are admin only
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.user))
        && !ApproverUsernames.get(Cast.toString(packet.user))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "ThisAccountCannotAccessThisInformation" });
        log('unapprovedProjects', `${packet.user} tried to access unapproved projects but they were not authorized to access them.`)
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`)
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted === false);
    let returnArray = projects;
    if (Cast.toBoolean(req.query.reverse)) {
        returnArray = structuredClone(returnArray).reverse();
    }
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
// pm wrappers so that pm code doesnt need to be changed in a major way
app.get('/api/pmWrapper/projects', async function (req, res) { // add featured projects and normal projects together
    const db = new Database(`${__dirname}/data/projects/published.json`)
    // this is explained in paged api but basically just add normal projects to featured projects
    // because otherwise featured projects would come after normal projects
    const featuredProjects = []
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).map(project => {
        return { id: project.id, name: project.name, author: { username: project.owner }, accepted: project.accepted, featured: project.featured };
    }).filter(proj => proj.accepted === true).filter(project => {
        if (project.featured) {
            featuredProjects.push(project);
        }
        return project.featured != true;
    });
    const returnArray = featuredProjects.concat(projects);
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
app.get('/api/pmWrapper/remixes', async function (req, res) { // get remixes of a project
    const packet = req.query;
    if (!packet.id) {
        res.status(400);
        res.json({ "error": "IdNotSpecified" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    // we dont care about featured projects here because remixes cant be featured
    const json = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.remix == packet.id).filter(proj => proj.accepted === true);
    const projectsList = new ProjectList(json);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
app.get('/api/pmWrapper/iconUrl', async function (req, res) { // get icon url of a project
    if (!req.query.id) {
        res.status(400);
        res.json({ "error": "IdNotSpecified" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    const json = db.get(String(req.query.id));
    if (!json) {
        res.status(400);
        res.json({ "error": "IdNotValid" });
        return;
    }
    fs.readFile(`${__dirname}/data/projects/uploadedImages/p${json.id}.gif`, (err, buffer) => {
        if (err) {
            res.status(404);
            res.json({
                "error": "ImageNotFoundOrErrorOccurred",
                "realerror": String(err)
            });
            return;
        }
        jimp.read(buffer).then(async image => {
            const width = Cast.toBoolean(req.query.widescreen) ? 640 : 480;
            image.cover(width / 2, 360 / 2, async (err, image) => {
                if (err) {
                    res.status(500);
                    res.json({
                        "error": "CompressionCroppingError",
                        "realerror": String(err)
                    });
                    return;
                }
                const buffer = await image.getBufferAsync(jimp.MIME_JPEG);
                res.status(200);
                res.contentType(jimp.MIME_JPEG);
                res.send(buffer);
            });
        }).catch(err => {
            res.status(500);
            res.json({
                "error": "CompressionError",
                "realerror": String(err)
            });
            return;
        });
    });
});
app.get('/api/pmWrapper/getProject', async function (req, res) { // get data of a(n approved) project
    if (!req.query.id) {
        res.status(400);
        res.json({ "error": "IdNotSpecified" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    const json = db.get(String(req.query.id));
    if (!json) {
        res.status(400);
        res.json({ "error": "IdNotValid" });
        return;
    }
    res.status(200);
    res.json({ id: json.id, name: json.name, author: { id: -1, username: json.owner, } });
});
// scratch auth implementation
app.get('/api/users/login', async function (req, res) { // login with scratch
    const privateCode = Cast.toString(req.query.privateCode);
    UserManager.verifyCode(privateCode).then(response => {
        // check if it is a malicious site
        // note: malicious sites cannot read the private code in the URL if it is the right redirect
        //       thank you cors, you finally did something useful

        // malicious APPS could, but at that point your just :trollface:d so :idk_man:
        const invalidRedirect = response.redirect !== 'https://snailshare.dreamhosters.com/api/users/login';
        if ((!response.valid) || (invalidRedirect)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidLogin" });
            if (invalidRedirect) {
                log('maliciousAuthentication', `${response.redirect} tried to falsely authenticate ${response.username}.`);
            }
            return;
        }
        // todo: we should clear the login after a couple days or so
        const username = response.username;
        UserManager.setCode(username, privateCode);
        if (!UserManager.getProperty(username, "firstLogin")) {
            UserManager.setProperty(username, "coins", 25)
            UserManager.setProperty(username, "firstLogin", Date.now());
        }
        // close window by opening success.html
        res.header("Content-Type", 'text/html');
        res.status(200);
        res.sendFile(path.join(__dirname, "./success.html"));
    }).catch(() => {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidLogin" });
    });
});
app.get('/api/users/loginLocal', async function (req, res) { // login with local account (like localhost)
    const privateCode = Cast.toString(req.query.privateCode);
    UserManager.verifyCode(privateCode).then(response => {
        // check if it is a malicious site
        // note: malicious sites cannot read the private code in the URL if it is the right redirect
        //       thank you cors, you finally did something useful

        // malicious APPS could, but at that point your just :trollface:d so :idk_man:
        const invalidRedirect =
            response.redirect !== 'https://snailshare-backend.glitch.me/api/users/loginLocal'
            && response.redirect !== 'http://localhost:8080/api/users/loginLocal';
        if ((!response.valid) || (invalidRedirect)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidLogin" });
            if (invalidRedirect) {
                console.log(response.redirect, "tried to falsely authenticate", response.username);
            }
            return;
        }
        // todo: we should clear the login after a couple days or so
        const username = response.username;
        UserManager.setCode(username, privateCode);
        if (!UserManager.getProperty(username, "firstLogin")) {
            UserManager.setProperty(username, "firstLogin", Date.now());
        }
        // close window by opening success.html
        res.header("Content-Type", 'text/html');
        res.status(200);
        res.sendFile(path.join(__dirname, "./success_local.html"));
    }).catch(() => {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidLogin" });
    });
});
// logout
app.get('/api/users/logout', (req, res) => { // logout
    if (!UserManager.isCorrectCode(req.query.user, req.query.code)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidLogin" });
        return;
    }
    UserManager.logoutUser(req.query.user);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": "LoginIsNowInvalidated" });
});
app.get('/api/users/usernameFromCode', async function (req, res) { // get username from private code
    const privateCode = Cast.toString(req.query.privateCode);
    const username = UserManager.usernameFromCode(privateCode);
    if (username == null) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CodeNotFound" });
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(GenerateProfileJSON(Cast.toString(username)));
});
// extra stuff
app.get('/api/users/isAdmin', async function (req, res) { // check if user is admin (by username)
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "admin": AdminAccountUsernames.get(Cast.toString(req.query.username)) });
});
app.get('/api/users/isApprover', async function (req, res) { // check if user is approver (by username)
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        "approver": ApproverUsernames.get(Cast.toString(req.query.username))
            || AdminAccountUsernames.get(Cast.toString(req.query.username))
    });
});
app.get('/api/users/getMyProjects', async function (req, res) { // get projects of a user (need username and private code)
    if (!UserManager.isCorrectCode(req.query.user, req.query.code)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    const projects = db.all().map(data => data.data).filter(project => project.owner === req.query.user);

    let result = projects;

    if (String(req.query.sorted) === "true") {
        result.sort((project, sproject) => {
            return sproject.date - project.date
        });
        const featuredProjects = [];
        const waitingProjects = [];
        const hiddenProjects = [];
        result = result.filter(project => {
            if (project.featured) {
                featuredProjects.push(project);
                return false;
            }
            if (!project.accepted) {
                waitingProjects.push(project);
                return false;
            }
            if (project.hidden) {
                hiddenProjects.push(project);
                return false;
            }
            return true;
        })
        const returnArray = featuredProjects.concat(result, waitingProjects, hiddenProjects);
        result = returnArray;
    }

    // paginate
    const projectsList = new ProjectList(result);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page), null, true);
    res.status(200)
    res.header("Content-Type", 'application/json');
    res.json(returning)
});

// MESSAGES
app.get('/api/users/getMessages', async function (req, res) { // get a users messages (you have to be the user) (by username and private code)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getMessages(packet.username);
    const messageList = new GenericList(messages);
    const returning = messageList.toJSON(true, Cast.toNumber(req.query.page));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(returning);
});
// we might not actually need this endpoint tbh
app.post('/api/users/addMessage', async function (req, res) { // add a message to a user (you have to be the user) (by username and private code)
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    // validate message (do we have perms? is this a valid message?)
    const unsafeMessage = packet.message;
    const invalidate = () => {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidMessage" });
    };
    const notallowed = () => {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CannotSendThisMessageType" });
    };

    // is this actually a message object?
    if (typeof unsafeMessage !== "object") return invalidate();
    if (Array.isArray(unsafeMessage)) return invalidate();

    // is the type of this message actually decided?
    if (typeof unsafeMessage.type !== "string") return invalidate();

    // check message type & add it
    const username = Cast.toString(packet.username);
    const target = packet.target;
    switch (unsafeMessage.type) {
        case 'custom':
            if (!AdminAccountUsernames.get(username)) return notallowed();
            if (typeof unsafeMessage.text !== "string") return invalidate();
            UserManager.addMessage(target, {
                type: unsafeMessage.type,
                text: unsafeMessage.text
            });
            break;
        default:
            return invalidate();
    }

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.get('/api/users/getMessageCount', async function (req, res) { // get a users message count (you have to be the user) (by username and private code)
    const packet = req.query;
    if (!UserManager.isCorrectCode(Cast.toString(packet.username), packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getUnreadMessages(Cast.toString(packet.username));
    res.status(200);
    res.header("Content-Type", 'text/plain');
    res.send(String(messages.length));
});
app.post('/api/users/markMessagesAsRead', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (packet.id) {
        UserManager.modifyMessage(packet.username, packet.id, (message) => ({
            ...message,
            read: true
        }));
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json({ "success": true });
        return;
    }
    if (packet.ids) {
        if (!Array.isArray(packet.ids)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "IDsMustBeArray" });
            return;
        }
        for (const id of packet.ids) {
            UserManager.modifyMessage(packet.username, id, (message) => ({
                ...message,
                read: true
            }));
        }
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json({ "success": true });
        return;
    }
    UserManager.markMessagesAsRead(packet.username);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// BADGES
app.get('/api/users/getBadges', async function (req, res) { // get a users badges (by username)
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!packet.username) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameNotSpecified" });
        return;
    }
    const badges = UserManager.getProperty(packet.username, "badges");
    if (!Array.isArray(badges)) {
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json([]);
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(badges);
});
app.post('/api/users/setBadges', async function (req, res) { // set a users badges (you must be an admin) (by username)
    const packet = req.body;
    if (!UserManager.isCorrectCode(Cast.toString(packet.username), packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const newBadges = packet.badges;
    const target = packet.target;
    if (typeof target !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetMustBeString" });
        return;
    }
    if (!target) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetNotSpecified" });
        return;
    }
    if (!Array.isArray(newBadges)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BadgesMustBeArray" });
        return;
    }
    UserManager.setProperty(target, "badges", newBadges);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        success: true,
        newbadges: UserManager.getProperty(target, "badges")
    });
});

// following
app.get('/api/users/getFollowerCount', async function (req, res) { // get a users follower count (by username)
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!packet.username) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameNotSpecified" });
        return;
    }
    const followers = UserManager.getFollowers(packet.username);
    if (!Array.isArray(followers)) {
        res.status(200);
        res.header("Content-Type", 'text/plain');
        res.send("0");
        return;
    }
    res.status(200);
    res.header("Content-Type", 'text/plain');
    res.send(Cast.toString(followers.length));
});
app.get('/api/users/isFollowing', async function (req, res) { // check if a user is following another user (by username)
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!packet.target) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetNotSpecified" });
        return;
    }
    const followers = UserManager.getFollowers(packet.target);
    if (!Array.isArray(followers)) {
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json({
            following: false,
            count: 0
        });
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        following: followers.includes(packet.username),
        count: followers.length
    });
});
app.post('/api/users/followToggle', async function (req, res) {
    const packet = req.body;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!packet.target) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetNotSpecified" });
        return;
    }
    const followers = UserManager.getFollowers(packet.target) ?? [];
    let isNowFollowing = true;
    if (followers.includes(packet.username)) {
        isNowFollowing = false;
        UserManager.removeFollower(packet.target, packet.username);
    } else {
        UserManager.addFollower(packet.target, packet.username);
    }
    if (isNowFollowing && !UserManager.getHadFollowers(packet.target).includes(packet.username)) {
        UserManager.addMessage(packet.target, {
            type: "followerAdded",
            name: `${packet.username}`
        });
        UserManager.addToUserFeed(packet.target, {
            type: "follow",
            username: packet.username
        });
    }
    // check if we can get followers badge
    if (UserManager.getFollowers(packet.target).length >= 50) {
        const badge = "followers";
        const newBadges = UserManager.getProperty(packet.target, "badges") ?? [];
        if (!newBadges.includes(badge)) {
            newBadges.push(badge);
            UserManager.setProperty(packet.target, "badges", newBadges);
            UserManager.addMessage(packet.target, {
                type: "newBadge",
                name: badge
            });
        }
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        following: isNowFollowing,
        count: (UserManager.getFollowers(packet.target) ?? []).length
    });
});

// FEED
app.get('/api/users/getMyFeed', async function (req, res) {
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const feed = UserManager.getUserFeed(packet.username);
    const messageList = new GenericList(feed);
    const returning = messageList.toJSON(true, Cast.toNumber(req.query.page ?? 0));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(returning);
});

// banning
app.post('/api/users/ban', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BanReasonIsRequired" });
        return;
    }
    if (packet.reason.length < 10) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BanReasonIsLessThan10Chars" });
        return;
    }

    const bannedUser = Cast.toString(packet.target);
    const bannedReason = Cast.toString(packet.reason);

    // ban
    UserManager.ban(bannedUser, bannedReason);
    // add message
    UserManager.addModeratorMessage(bannedUser, {
        type: "ban",
        reason: packet.reason,
        disputable: true
    });

    log('ban', `${packet.username} banned user ${packet.target} because of the reason "${packet.reason}".`)
    // post log
    const body = JSON.stringify({
        content: `${bannedUser} was banned by ${packet.username}`,
        embeds: [{
            title: `${bannedUser} was banned`,
            color: 0xff0000,
            fields: [
                {
                    name: "Banned by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${bannedReason}`
                }
            ],
            author: {
                name: String(bannedUser).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(bannedUser).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(bannedUser).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) {
            res.status(200);
            res.header("Content-Type", 'application/json');
            res.json({ "success": true });
        } else {
            res.status(500);
            res.header('Content-Type', 'application/json')
            res.json({ error: 'LogFailed' })
        }
    });
});
app.post('/api/users/unban', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UnbanReasonIsRequired" });
        return;
    }

    const bannedUser = Cast.toString(packet.target);
    const bannedReason = Cast.toString(packet.reason);

    // unban
    UserManager.unban(bannedUser);
    // add message
    UserManager.addModeratorMessage(bannedUser, {
        type: "unban",
        reason: packet.reason,
        disputable: false // why would you dispute an unban? lmfao
    });

    // post log
    const body = JSON.stringify({
        content: `${bannedUser} was unbanned by ${packet.username}`,
        embeds: [{
            title: `${bannedUser} was unbanned`,
            color: 0x00ff00,
            fields: [
                {
                    name: "Unbanned by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${bannedReason}`
                }
            ],
            author: {
                name: String(bannedUser).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(bannedUser).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(bannedUser).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) {
            res.status(200);
            res.header("Content-Type", 'application/json');
            res.json({ "success": true });
        } else {
            res.status(500);
            res.header('Content-Type', 'application/json')
            res.json({ error: 'LogFailed' })
        }
    });
});
// COINS
app.post('/api/users/givecoins', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const usertogive = Cast.toString(packet.target);

    // give coins
    UserManager.givecoins(usertogive);
    // add message
    UserManager.addModeratorMessage(usertogive, {
        type: "coins",
        reason: "Congrats! You have been given coins from a mod!",
        disputable: false // lol
    });

    // post log
    const body = JSON.stringify({
        content: `${usertogive} was given coins by ${packet.username}`,
        embeds: [{
            title: `${usertogive} was given coins`,
            color: 0x00ff00,
            fields: [
                {
                    name: "Given coins by",
                    value: `${packet.username}`
                },
                {
                    name: "idklol",
                    value: `${usertogive}`
                }
            ],
            author: {
                name: String(usertogive).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(usertogive).substring(0, 50)),
                url: String("https://snailshare.vercel.app/profile?user=" + String(usertogive).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) {
            res.status(200);
            res.header("Content-Type", 'application/json');
            res.json({ "success": true });
        } else {
            res.status(500);
            res.header('Content-Type', 'application/json')
            res.json({ error: 'LogFailed' })
        }
    });
});

// REPORTING
// users
app.get('/api/users/report', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reportedUser = Cast.toString(packet.target);
    const reportedReason = Cast.toString(packet.reason).substring(0, 2048);

    globalOperationCounter++;
    const id = `repu-${Date.now()}-${globalOperationCounter}`;
    UserManager.addReport(reportedUser, {
        reason: reportedReason,
        reporter: packet.username,
        id
    }, true);

    const body = JSON.stringify({
        content: `${reportedUser} was reported by ${packet.username}`,
        embeds: [{
            title: `${reportedUser} was reported`,
            color: 0xff0000,
            fields: [
                {
                    name: "Reported by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${reportedReason}`
                }
            ],
            author: {
                name: String(reportedUser).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(reportedUser).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(reportedUser).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.get('/api/users/getReports', async function (req, res) {
    const packet = req.query;
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reports = UserManager.getReports(Cast.toString(packet.target));
    const mergedReports = new ReportList(reports).toMerged();
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(mergedReports);
});
app.get('/api/users/getContentWithReports', async function (req, res) {
    const packet = req.query;
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reports = UserManager.getAllReports();
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(reports
        .sort((user, suser) => suser.data.length - user.data.length)
        .map(r => ({
            username: r.key,
            reports: r.data.length
        })));
});
app.post('/api/users/deleteReports', async function (req, res) {
    const packet = req.body;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }
    if (typeof packet.target !== "string") {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoTargetSpecified" });
        return;
    }

    const reportDB = new Database(`${__dirname}/data/userreports.json`);
    const reportedUsername = Cast.toString(packet.id);
    if (!reportDB.has(reportedUsername)) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoUserReportsFound" });
        return;
    }
    const reports = reportDB.get(reportedUsername);
    const newReports = reports.filter(report => report.reporter !== packet.target);
    if (newReports.length <= 0) {
        reportDB.delete(reportedUsername);
    } else {
        reportDB.set(reportedUsername, newReports);
    }

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json({ success: true });
});
// projects
app.get('/api/projects/report', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reportedProject = Cast.toString(packet.target);
    const reportedReason = Cast.toString(packet.reason).substring(0, 2048);

    const db = new Database(`${__dirname}/data/projects/published.json`);
    const project = db.get(reportedProject);
    if (!project) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NotFound" });
        return;
    }

    const reportDB = new Database(`${__dirname}/data/projectreports.json`);
    let projectReports = reportDB.get(reportedProject);
    if (!Array.isArray(projectReports)) projectReports = [];

    globalOperationCounter++;
    const id = `rep-${Date.now()}-${globalOperationCounter}`;
    projectReports.push({ reason: reportedReason, reporter: packet.username, id });
    reportDB.set(reportedProject, projectReports);
    UserManager.punishSameUserReports(projectReports, packet.username, `Project ${reportedProject}`);

    const body = JSON.stringify({
        content: `Project ${reportedProject} was reported by ${packet.username}`,
        embeds: [{
            title: `Project ${reportedProject} was reported`,
            color: 0xff0000,
            fields: [
                {
                    name: "Reported by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${reportedReason}`
                }
            ],
            author: {
                name: String(packet.username).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.username).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json({ success: true });
});
app.get('/api/projects/getReports', async function (req, res) {
    const packet = req.query;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }
    const projectId = Cast.toString(packet.target);

    const db = new Database(`${__dirname}/data/projects/published.json`);
    const project = db.get(projectId);
    if (!project) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NotFound" });
        return;
    }

    const reportDB = new Database(`${__dirname}/data/projectreports.json`);
    let projectReports = reportDB.get(projectId);
    if (!Array.isArray(projectReports)) projectReports = [];
    const mergedReports = new ReportList(projectReports).toMerged();

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json(mergedReports);
});
app.get('/api/projects/getContentWithReports', async function (req, res) {
    const packet = req.query;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reportDB = new Database(`${__dirname}/data/projectreports.json`);
    const allReports = reportDB.all();
    const projectDB = new Database(`${__dirname}/data/projects/published.json`);

    const properFormattedReports = allReports
        .sort((project, sproject) => sproject.data.length - project.data.length)
        .map(r => ({
            id: r.key,
            reports: r.data.length
        }));
    for (const content of properFormattedReports) {
        const project = projectDB.get(content.id);
        if (project) {
            content.exists = true;
            content.author = project.owner;
            content.name = project.name;
        } else {
            content.exists = false;
        }
    }

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json(properFormattedReports);
});
app.post('/api/projects/deleteReports', async function (req, res) {
    const packet = req.body;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }
    if (typeof packet.target !== "string") {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoTargetSpecified" });
        return;
    }

    const reportDB = new Database(`${__dirname}/data/projectreports.json`);
    const projectId = Cast.toString(packet.id);
    if (!reportDB.has(projectId)) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoProjectFound" });
        return;
    }
    const reports = reportDB.get(projectId);
    const newReports = reports.filter(report => report.reporter !== packet.target);
    if (newReports.length <= 0) {
        reportDB.delete(projectId);
    } else {
        reportDB.set(projectId, newReports);
    }

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json({ success: true });
});

// DISPUTE
app.post('/api/users/dispute', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getMessages(packet.username);
    const message = messages.filter(message => message.id === packet.id)[0];
    if (!message) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    if (!message.disputable) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MessageNotDisputable" });
        return;
    }

    for (let [key, value] of Object.entries(AdminAccountUsernames.all())) {
        if (value.data === true) UserManager.addMessage(value.key, {
            reply: `${packet.text}`,
            type: "dispute",
            replyTo: `${message.reason ? message.reason : ''}`,
            projectId: `${message.projectData ? message.projectData.id : '(not applicable)'}`,
            id: packet.id,
            user: packet.username, // included for less API calls
        })
    }

    // post log
    /* const body = JSON.stringify({
        content: `${packet.username} replied to moderator message`,
        embeds: [{
            title: `Reply by ${packet.username}`,
            color: 0xff8800,
            fields: [
                {
                    name: "Message Replied to",
                    value: `${message.reason ? message.reason : ''}\n\n\`\`${message.type} (${message.id})\`\``
                },
                {
                    name: "Project ID (if applicable)",
                    value: `${message.projectData ? message.projectData.id : '(not applicable)'}`
                },
                {
                    name: "Reply",
                    value: `${packet.text}`
                }
            ],
            author: {
                name: String(packet.username).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.username).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    }); */
    /* fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) { */
    UserManager.modifyMessage(packet.username, packet.id, message => {
        message.disputable = false;
        message.dispute = packet.text ?? ''
        return message;
    });

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
    /* } else {
        res.status(500);
        res.header('Content-Type', 'application/json')
        res.json({ error: 'LogFailed' })
    }
}); */
});
app.get('/api/getLog', function (req, res) {
    const db = new Database(`${__dirname}/data/log.json`);
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    return res.json(db.get('logs'));
});
app.get('/api/backup', function (req, res) {
    const packet = req.query;
    const child_process = require('child_process');
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    log('dataRequested', `${packet.user} requested a copy of all data.`)
    console.log(`zip -r ./data.zip ./data/`);
    child_process.execSync(`zip -r './data.zip' './data/'`);
    res.sendFile(`${__dirname}/data.zip`, () => {
        fs.unlinkSync(`${__dirname}/data.zip`);
    });
});
app.post('/api/users/disputeRespond', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const messages = UserManager.getMessages(packet.username);
    const message = messages.filter(message => message.id === packet.id)[0];
    if (packet.id !== '' && !message) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    if (message && !message.type === 'reject') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MessageNotDisputable" });
        return;
    }

    if (!message) {
        UserManager.addModeratorMessage(packet.username, {
            type: "modMessage",
            reason: packet.reason,
            disputable: true
        });
        res.status(200);
        res.header("Content-Type", 'application/json');
        return res.json({ "success": true });
    }

    // add message
    UserManager.addModeratorMessage(packet.username, {
        disputeId: String(packet.id),
        type: "disputeResponse",
        reason: packet.reason,
        disputable: true
    });

    /* // post log
    const body = JSON.stringify({
        content: `${packet.approver} responded to reply from ${packet.username}`,
        embeds: [{
            title: `${packet.approver} responded to a reply`,
            color: 0x6600ff,
            fields: [
                {
                    name: "Message ID",
                    value: `${message.id}`
                },
                {
                    name: "Original Reply",
                    value: `${message.dispute ? message.dispute : '(reply is too old, search message ID in logs)'}`
                },
                {
                    name: "Moderator Reply",
                    value: `${packet.reason}`
                }
            ],
            author: {
                name: String(packet.username).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.username).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
    }); */

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// approve uploaded projects
app.get('/api/projects/approve', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(packet.id)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }

    // newMeta
    // replace
    let isUpdated = false;
    let isRemix = false;

    let idToSetTo = packet.id;
    // idk if db uses a reference to the object or not
    const project = JSON.parse(JSON.stringify(db.get(Cast.toString(packet.id))));
    if (project.updating) {
        isUpdated = true;
    }
    project.updating = false;
    project.accepted = true;
    if (Cast.toBoolean(project.remix)) isRemix = true;
    db.set(String(idToSetTo), project);

    UserManager.notifyFollowers(project.owner, {
        type: "upload",
        username: project.owner,
        content: {
            id: project.id,
            name: project.name
        }
    });
    if (isRemix) {
        if (db.has(String(project.remix))) {
            const remixedProject = db.get(String(project.remix));
            UserManager.addMessage(remixedProject.owner, {
                type: "remix",
                projectId: remixedProject.id,
                name: `${remixedProject.name}`, // included for less API calls
                remixId: project.id,
                remixName: project.name,
            });
            UserManager.addToUserFeed(remixedProject.owner, {
                type: "remixed",
                username: remixedProject.owner,
                content: {
                    id: remixedProject.id,
                    name: remixedProject.name
                }
            });
        }
    }
    {
        // post log
        const projectImage = String(`https://snailshare-backend.glitch.me/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
        const body = JSON.stringify({
            content: `"${project.name}" was approved by ${packet.approver}`,
            embeds: [{
                title: `${project.name} was approved`,
                color: 0x00ff00,
                image: { url: projectImage },
                url: "https://snail-ide.js.org/#" + project.id,
                fields: [
                    {
                        name: "Approved by",
                        value: `${packet.approver}`
                    }
                ],
                author: {
                    name: String(project.owner).substring(0, 50),
                    icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                    url: String("https://snail-ide.vercel.app/profile?user=" + String(project.owner).substring(0, 50))
                },
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.ApproverLogWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(JSON.parse(body))
        });
    }

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });

    if (Cast.toBoolean(req.query.webhook) === false) return;
    const projectImage = String(`https://snailshare-backend.glitch.me/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
    const body = JSON.stringify({
        content: `A project was ${isUpdated ? "updated" : (isRemix ? "remixed" : "approved")}!`,
        embeds: [{
            title: String(project.name).substring(0, 250),
            description: String(project.instructions + "\n\n" + project.notes).substring(0, 2040),
            image: { url: projectImage },
            color: (isUpdated ? 14567657 : (isRemix ? 6618880 : 41440)),
            url: String("https://snail-ide.js.org/#" + String(project.id)),
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(project.owner).substring(0, 50))
            }
        }]
    });
    fetch(process.env.DiscordWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
    });
    // .then(res => res.text().then(t => console.log("WebhookResponse",res.status,t))).catch(err => console.log("FailedWebhookSend", err))
});
// nfe projects
app.post('/api/projects/nfe', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NFEReasonIsRequired" });
        return;
    }
    if (packet.reason.length < 10) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NFEReasonIsLessThan10Chars" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(String(packet.id))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(packet.id));
    log('projectMarkedAsNFE', `${packet.approver} marked https://snail-ide.js.org/#${packet.id} by https://www.snail-ide.com/profile?user=${String(project.owner)} as Not for Everyone with the reason "${packet.reason}".`);
    UserManager.addModeratorMessage(project.owner, {
        projectId: String(packet.id),
        type: "nfe",
        name: `${project.name}`, // included for less API calls
        reason: packet.reason,
        projectData: project,
        disputable: true
    });
    project.nfe = true;
    db.set(String(packet.id), project);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.post('/api/projects/undoNfe', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(String(packet.id))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(packet.id));
    log('projectMarkedAsNotNFE', `${packet.approver} removed the mark for https://snail-ide.js.org/#${packet.id} by https://www.snail-ide.com/profile?user=${String(project.owner)} as Not for Everyone.`);
    project.nfe = false;
    db.set(String(packet.id), project);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// reject projects
app.post('/api/projects/reject', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "RejectionReasonIsRequired" });
        return;
    }
    if (packet.reason.length < 10) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "RejectionReasonIsLessThan10Chars" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(String(packet.id))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(packet.id));
    // if (project.accepted) {
    //     res.status(403);
    //     res.header("Content-Type", 'application/json');
    //     res.json({ "error": "CannotRejectApprovedProject" });
    //     return;
    // }
    // post log
    log('projectRejected', `${packet.approver} rejected https://snail-ide.js.org/#${packet.id} by https://www.snail-ide.com/profile?user=${String(project.owner)} with the reason "${packet.reason}".`);
    // add message
    UserManager.addModeratorMessage(project.owner, {
        projectId: String(packet.id),
        type: "reject",
        name: `${project.name}`, // included for less API calls
        reason: packet.reason,
        projectData: project,
        disputable: true
    });
    db.delete(String(packet.id));
    const projectFilePath = `${__dirname}/data/projects/uploaded/p${packet.id}.snail`;
    const projectImagePath = `${__dirname}/data/projects/uploadedImages/p${packet.id}.gif`;
    const backupProjectMetaPath = `${__dirname}/data/projects/backup/proj${packet.id}.json`;
    fs.writeFile(backupProjectMetaPath, JSON.stringify(project, null, 4), 'utf8', (err) => {
        if (err) return console.log('failed to backup project meta for', packet.id);
    });
    fs.readFile(projectFilePath, (err, data) => {
        if (err) return console.log('failed to open project file for', packet.id, ', will not be deleted from rejection');
        fs.writeFile(`${__dirname}/data/projects/backup/proj${packet.id}.pmp`, data, (err) => {
            if (err) return console.log('failed to backup project file for', packet.id, ', will not be deleted from rejection');
            fs.unlink(projectFilePath, err => {
                if (err) console.log("failed to delete project data for", packet.id, ";", err);
            });
        });
    });
    fs.readFile(projectImagePath, (err, data) => {
        if (err) return console.log('failed to open image for', packet.id, ', will not be deleted from rejection');
        fs.writeFile(`${__dirname}/data/projects/backup/proj${packet.id}.gif`, data, (err) => {
            if (err) return console.log('failed to backup project image for', packet.id, ', will not be deleted from rejection');
            fs.unlink(projectImagePath, err => {
                if (err) console.log("failed to delete project image for", packet.id, ";", err);
            });
        });
    });
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// RELATED TO ALREADY REJECTED PROJECTS
app.get('/api/projects/downloadRejected', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        const allowed = await new Promise((resolve) => {
            const backupProjectMetaPath = `${__dirname}/data/projects/backup/proj${packet.id}.json`;
            fs.readFile(backupProjectMetaPath, 'utf8', (err, data) => {
                if (err) {
                    // this was rejected so long ago that we really dont care that anyone can download it
                    return resolve(true);
                }
                const projectMeta = SafeJSONParse(data);
                resolve(projectMeta.owner === packet.approver);
            });
        });
        if (!allowed) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    const projectDataPath = `${__dirname}/data/projects/backup/proj${packet.id}.pmp`;
    fs.readFile(projectDataPath, (err) => {
        if (err) {
            res.status(404);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "ProjectNotFound" });
            return;
        }
        res.status(200);
        res.sendFile(path.join(__dirname, projectDataPath));
    });
});
app.post('/api/projects/restoreRejected', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    // attempt to restore
    const db = new Database(`${__dirname}/data/projects/published.json`);
    const projectId = packet.id;

    const backupProjectFilePath = `${__dirname}/data/projects/backup/proj${projectId}.pmp`;
    const backupProjectImagePath = `${__dirname}/data/projects/backup/proj${projectId}.gif`;
    const backupProjectMetaPath = `${__dirname}/data/projects/backup/proj${projectId}.json`;

    const restoredProjectFilePath = `${__dirname}/data/projects/uploaded/p${projectId}.snail`;
    const restoredProjectImagePath = `${__dirname}/data/projects/uploadedImages/p${projectId}.gif`;
    // PROJECT FILE
    fs.readFile(backupProjectFilePath, (err, data) => {
        if (err) {
            console.warn('couldnt restore file for', projectId, err);
            return;
        }
        fs.writeFile(restoredProjectFilePath, data, (err) => {
            if (err) {
                console.warn('couldnt restore file for', projectId, err);
                return;
            }
        })
    });
    // PROJECT IMAGE
    fs.readFile(backupProjectImagePath, (err, data) => {
        if (err) {
            console.warn('couldnt restore image for', projectId, err);
            return;
        }
        fs.writeFile(restoredProjectImagePath, data, (err) => {
            if (err) {
                console.warn('couldnt restore image for', projectId, err);
                return;
            }
        })
    });
    // PROJECT META
    fs.readFile(backupProjectMetaPath, 'utf8', (err, data) => {
        if (err) {
            // search userMessages instead
            let projectMetadata = {
                "id": projectId,
                "name": "Unknown Project " + projectId,
                "instructions": "",
                "notes": "This project was restored, but it's information was missing or corrupted.\nPlease edit the project to restore this information.\n",
                "owner": packet.approver, // we dont know the owner
                "featured": false,
                "accepted": true,
                "date": Date.now(),
                "views": 0,
                "loves": [],
                "votes": [],
                "updating": false
            };
            const messageData = UserManager.getRawMessageData();
            for (const username in messageData) {
                for (const message of messageData[username]) {
                    if (message.type === 'reject' && message.projectData) {
                        if (message.projectData.id === projectId) {
                            projectMetadata = message.projectData;
                            break;
                        }
                    }
                }
            }
            const usingData = {
                ...projectMetadata,
                accepted: true,
                featured: false
            }
            if (usingData.owner) {
                UserManager.addModeratorMessage(usingData.owner, {
                    type: "restored",
                    projectId,
                    name: `${usingData.name}` // included for less API calls
                });
            }
            db.set(Cast.toString(projectId), usingData);
            return;
        }
        let projectMeta;
        try {
            projectMeta = JSON.parse(data);
        } catch (err) {
            console.warn('couldnt restore metadata for', projectId, err);
            return;
        }
        const usingData = {
            ...projectMeta,
            accepted: true,
            featured: false
        }
        if (usingData.owner) {
            UserManager.addModeratorMessage(usingData.owner, {
                type: "restored",
                projectId,
                name: `${usingData.name}` // included for less API calls
            });
        }
        db.set(Cast.toString(projectId), usingData);
    });

    // valid info
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.post('/api/projects/deleteRejected', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        // && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    // attempt to delete
    const projectId = packet.id;

    const backupProjectFilePath = `${__dirname}/data/projects/backup/proj${projectId}.pmp`;
    const backupProjectImagePath = `${__dirname}/data/projects/backup/proj${projectId}.gif`;
    const backupProjectMetaPath = `${__dirname}/data/projects/backup/proj${projectId}.json`;
    // PROJECT FILE
    fs.unlink(backupProjectFilePath, (err) => {
        if (err) {
            console.warn('couldnt delete file for', projectId, err);
            return;
        }
    });
    // PROJECT IMAGE
    fs.unlink(backupProjectImagePath, (err) => {
        if (err) {
            console.warn('couldnt delete image for', projectId, err);
            return;
        }
    });
    // PROJECT META
    fs.unlink(backupProjectMetaPath, (err) => {
        if (err) {
            console.warn('couldnt delete metadata for', projectId, err);
            return;
        }
    });

    // valid info
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// feature uploaded projects
app.get('/api/projects/feature', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.approver))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const idToSetTo = String(packet.id);
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(idToSetTo)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    // idk if db uses a reference to the object or not
    const project = JSON.parse(JSON.stringify(db.get(idToSetTo)));
    if (!project.accepted) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CantFeatureUnapprovedProject" });
        return;
    }
    // if (project.votes.length < 6) {
    //     res.status(400);
    //     res.header("Content-Type", 'application/json');
    //     res.json({ "error": "CantFeatureProjectWithLessThan6Votes" });
    //     return;
    // }
    project.featured = true;
    db.set(String(idToSetTo), project);
    UserManager.addMessage(project.owner, {
        type: "featured",
        projectId: idToSetTo,
        name: `${project.name}` // included for less API calls
    });
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
    if (Cast.toBoolean(req.query.webhook) === false) return;
    const projectImage = String(`https://snailshare-backend.glitch.me/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
    const projectTitle = String(project.name).substring(0, 250);
    const body = JSON.stringify({
        content: `⭐ **${projectTitle}** was **featured**! ⭐`,
        embeds: [{
            title: projectTitle,
            image: { url: projectImage },
            color: 16771677,
            url: String("https://snail-ide.js.org/#" + String(project.id)),
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://snail-ide.vercel.app/profile?user=" + String(project.owner).substring(0, 50))
            }
        }]
    });
    fetch(process.env.DiscordWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
    });
    // .then(res => res.text().then(t => console.log("WebhookResponse",res.status,t))).catch(err => console.log("FailedWebhookSend", err))
});
// toggle liking or voting for uploaded projects
app.post('/api/projects/toggleProjectVote', async function (req, res) {
    const packet = req.body;
    const username = String(packet.user);
    if (!UserManager.isCorrectCode(username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const idToSetTo = String(packet.id);
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(idToSetTo)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    // idk if db uses a reference to the object or not
    const project = structuredClone(db.get(idToSetTo));
    if ((packet.type === 'votes') && (!project.accepted)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CantVoteUnapprovedProject" });
        return;
    }
    let targetType = 'loves';
    if (packet.type === 'votes') {
        targetType = 'votes';
    }
    // old projects dont have these props set
    if (!Array.isArray(project[targetType])) {
        project[targetType] = [];
    }
    // we add this
    const userValue = encrypt(username);
    let voted = true;
    const decryptedUsernames = DecryptArray(project[targetType]);
    if (decryptedUsernames.includes(username)) {
        // remove the vote
        const newArray = structuredClone(decryptedUsernames);
        const idx = newArray.indexOf(username);
        newArray.splice(idx, 1);
        project[targetType] = EncryptArray(newArray);
        voted = false;
    } else {
        // add encrypted name to the raw list, we dont need to edit decrypted
        project[targetType].push(userValue);
    }
    console.log('updated', targetType, 'on', project.id, 'to', project[targetType].length);
    const featuredVotes = Cast.toNumber(process.env.VotesRequiredForFeature);
    if (project[targetType].length > 50) {
        let badge = "likes";
        if (targetType === 'votes') {
            badge = "votes";
        }
        const newBadges = UserManager.getProperty(project.owner, "badges") ?? [];
        if (!newBadges.includes(badge)) {
            newBadges.push(badge);
            UserManager.setProperty(project.owner, "badges", newBadges);
            UserManager.addMessage(project.owner, {
                type: "newBadge",
                name: badge
            });
        }
    }
    if ((targetType === 'votes') && (project.votes.length >= featuredVotes)) {
        if (featuredVotes === 0) {
            warnings += 1;
            log('warning', `Warning: Project ${String("https://snail-ide.js.org/#" + String(project.id))} should of been featured but the featured votes variable is set to null or zero. Refusing to feature project.`);
        }
        // people lik this project
        if (featuredVotes !== 0) {
            let wasFeatured = project.featured;
            project.featured = true;
            project.featured = true;
            if (!wasFeatured) {
                UserManager.addMessage(project.owner, {
                    type: "featured",
                    projectId: project.id,
                    name: `${project.name}` // included for less API calls
                });
            }
            const newBadges = UserManager.getProperty(project.owner, "badges") ?? [];
            if (!newBadges.includes("featured")) {
                newBadges.push("featured");
                UserManager.setProperty(project.owner, "badges", newBadges);
                UserManager.addMessage(project.owner, {
                    type: "newBadge",
                    name: "featured"
                });
            }
            log('projectFeatured', `Project ${String("https://snail-ide.js.org/#" + String(project.id))} has been featured! Hooray!`)
        }
    }
    db.set(idToSetTo, project);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "state": voted });
});
app.get('/api/projects/getProjectVote', async function (req, res) {
    const packet = req.query;
    const username = String(packet.user);
    if (!UserManager.isCorrectCode(username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const idToSetTo = String(packet.id);
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(idToSetTo)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    // idk if db uses a reference to the object or not
    const project = JSON.parse(JSON.stringify(db.get(idToSetTo)));
    if (!Array.isArray(project.loves)) {
        project.loves = [];
    }
    if (!Array.isArray(project.votes)) {
        project.votes = [];
    }
    // const userValue = encrypt(username);
    const loved = DecryptArray(project.loves).includes(username);
    const voted = DecryptArray(project.votes).includes(username);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "loved": loved, "voted": voted });
});
// delete uploaded projects
app.get('/api/projects/delete', async function (req, res) {
    // todo: should we make backups of these? remember, uploaded projects are NOT save files
    //       in-progress projects are not going to be a thing so remember that if we decide
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const db = new Database(`${__dirname}/data/projects/published.json`);
    if (!db.has(packet.id)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(packet.id))
    if (project.owner !== packet.approver) {
        if (!AdminAccountUsernames.get(Cast.toString(packet.approver))) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    db.delete(String(packet.id));
    fs.unlink(`${__dirname}/data/projects/uploaded/p${packet.id}.snail`, err => {
        if (err) console.log("failed to delete project data for", packet.id, ";", err);
    })
    fs.unlink(`${__dirname}/data/projects/uploadedImages/p${packet.id}.gif`, err => {
        if (err) console.log("failed to delete project image for", packet.id, ";", err);
    })
    console.log(packet.approver, "deleted", packet.id);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// update uploaded projects
// todo: replace /approve's newMeta stuff with this endpoint?
app.post('/api/projects/update', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.requestor, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }

    if (UserManager.isBanned(packet.requestor)) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const db = new Database(`${__dirname}/data/projects/published.json`);
    const id = String(packet.id);
    if (!db.has(id)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(id));
    const projectWasApproved = project.accepted;
    if (project.owner !== packet.requestor) {
        if (!AdminAccountUsernames.get(Cast.toString(packet.requestor))) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    if (typeof packet.newMeta === "string") {
        const newMetadata = SafeJSONParse(packet.newMeta);
        let updatingProject = false;
        if (typeof newMetadata.name === "string") {
            project.name = newMetadata.name;
            if (CheckForIllegalWording(newMetadata.name)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "IllegalWordsUsed" });
                if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
                return;
            }
            if (newMetadata.name.length < 3 || newMetadata.name.length > 50) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Title3-50Chars" });
                if (DEBUG_logAllFailedData) console.log("Title3-50Chars", packet);
                return;
            }
            updatingProject = true;
        }
        if (typeof newMetadata.instructions === "string") {
            project.instructions = newMetadata.instructions;
            if (CheckForIllegalWording(newMetadata.instructions)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "IllegalWordsUsed" });
                if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
                return;
            }
            if (newMetadata.instructions && (newMetadata.instructions.length > 4096)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Instructions4096Longer" });
                if (DEBUG_logAllFailedData) console.log("Instructions4096Longer", packet);
                return;
            }
            updatingProject = true;
        }
        if (typeof newMetadata.notes === "string") {
            project.notes = newMetadata.notes;
            if (CheckForIllegalWording(newMetadata.notes)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "IllegalWordsUsed" });
                if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
                return;
            }
            if (newMetadata.notes && (newMetadata.notes.length > 4096)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Notes4096Longer" });
                if (DEBUG_logAllFailedData) console.log("Notes4096Longer", packet);
                return;
            }
            updatingProject = true;
        }
        // if yea then do
        if (updatingProject) {
            project.accepted = true;
            project.featured = false;
            project.updating = true;
            project.date = Date.now();
        }
    }

    const projectBufferData = packet.project;
    if (Cast.isString(projectBufferData)) {
        const buffer = Cast.dataURLToBuffer(projectBufferData);
        if (buffer) {
            const zip = await safeZipParse(buffer);
            if (!zip) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "MissingProjectData" });
                if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
                return;
            }
            // DEBUG
            // fs.writeFile(`./cache/project.json`, await zip.file("project.json").async("string"), (err) => {
            //     if (err) console.error(err);
            // });
            if (!zip.file("project.json")) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "MissingProjectData" });
                if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
                return;
            }
            const rawProjectCodeJSON = await zip.file("project.json").async("string");
            const projectCodeJSON = SafeJSONParse(rawProjectCodeJSON);
            if (!projectCodeJSON.meta) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "MissingProjectData" });
                if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
                return;
            }
            // ok yea project stuff exists
            // are we a low rank?
            const userRank = Cast.toNumber(UserManager.getProperty(packet.requestor, "rank"));
            if (userRank < 1) {
                if (projectCodeJSON.extensions) {
                    // check extensions
                    const isUrlExtension = (extId) => {
                        if (!projectCodeJSON.extensionURLs) return false;
                        return (extId in projectCodeJSON.extensionURLs);
                    };
                    for (let extension of projectCodeJSON.extensions) {
                        let isUrl = isUrlExtension(extension);
                        if (isUrl) {
                            extension = projectCodeJSON.extensionURLs[extension];
                        }
                        if (!checkExtensionIsAllowed(extension, isUrl)) {
                            res.status(403);
                            res.header("Content-Type", 'application/json');
                            res.json({ error: "CannotUseThisExtensionForThisRank", isUrl, extension });
                            if (DEBUG_logAllFailedData) console.log("CannotUseThisExtensionForThisRank", packet);
                            return;
                        }
                    }
                }
            }
            fs.writeFile(`${__dirname}/data/projects/uploaded/p${id}.snail`, buffer, (err) => {
                if (err) console.error(err);
            });
        }
        project.accepted = true;
        project.featured = false;
        project.updating = true;
        project.date = Date.now();
    }
    const projectbufferImage = packet.image;
    if (Cast.isString(projectbufferImage)) {
        const buffer = Cast.dataURLToBuffer(projectbufferImage);
        if (buffer) {
            fs.writeFile(`${__dirname}/data/projects/uploadedImages/p${id}.gif`, buffer, (err) => {
                if (err) console.error(err);
            });
        }
        project.accepted = true;
        project.featured = false;
        project.updating = true;
        project.date = Date.now();
    }
    // if project is not accepted, make a log for approvers
    // if (projectWasApproved && !project.accepted) {
    //     // post log
    //     const body = JSON.stringify({
    //         content: `"${project.name}" was updated by ${project.owner}`,
    //         embeds: [{
    //             title: `${project.name} was updated`,
    //             color: 0x00bbff,
    //             fields: [
    //                 {
    //                     name: "Owner",
    //                     value: `${project.owner}`
    //                 },
    //                 {
    //                     name: "ID",
    //                     value: `${project.id}`
    //                 }
    //             ],
    //             author: {
    //                 name: String(project.owner).substring(0, 50),
    //                 icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
    //                 url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
    //             },
    //             timestamp: new Date().toISOString()
    //         }]
    //     });
    //     fetch(process.env.ApproverLogWebhook, {
    //         method: "POST",
    //         headers: { "Content-Type": "application/json" },
    //         body: body
    //     });
    // }
    // set in DB
    db.set(String(id), project);
    console.log(packet.requestor, "updated", id);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// upload project to the main page
const UploadsDisabled = Cast.toBoolean(process.env.UploadsDisabled);
app.post('/api/projects/publish', async function (req, res) {
    const packet = req.body;
    if (UploadsDisabled && (!AdminAccountUsernames.get(Cast.toString(packet.author)))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "PublishDisabled" });
        return;
    }
    if (UserManager.isBanned(packet.author)) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    if (!UserManager.isCorrectCode(packet.author, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        if (DEBUG_logAllFailedData) console.log("Reauthenticate", packet);
        return;
    }

    // cooldown check
    let db = new Database(`${__dirname}/data/cooldown.json`);
    const cooldown = Number(db.get(Cast.toString(packet.author)));
    if (Date.now() < cooldown) {
        res.status(429);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TooManyRequests" });
        return;
    }

    if (!(packet.title && packet.author)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingTitleAuthorReference" });
        if (DEBUG_logAllFailedData) console.log("MissingTitleAuthorReference", packet);
        return;
    }
    if (!packet.project) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }

    if (
        (typeof packet.title !== "string") ||
        (typeof packet.author !== "string")
    ) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError" });
        if (DEBUG_logAllFailedData) {
            console.log("FormatError", packet);
            fs.writeFile("./temp.log", JSON.stringify(packet), err => {
                if (err) console.log(err);
            });
        };
        return;
    }
    if (
        !Cast.isString(packet.project)
    ) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError2" });
        if (DEBUG_logAllFailedData) {
            console.log("FormatError2", packet);
            fs.writeFile("./temp.log", JSON.stringify(packet), err => {
                if (err) console.log(err);
            });
        };
        return;
    }
    if (packet.instructions && (typeof packet.instructions !== "string")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError" });
        if (DEBUG_logAllFailedData) console.log("FormatError", packet);
        return;
    }
    if (packet.notes && (typeof packet.notes !== "string")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError" });
        if (DEBUG_logAllFailedData) console.log("FormatError", packet);
        return;
    }
    if (packet.remix && (typeof packet.remix !== "number")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatErrorRemixMustBeProjectIdAsNumber" });
        if (DEBUG_logAllFailedData) console.log("FormatErrorRemixMustBeProjectIdAsNumber", packet);
        return;
    }
    if (packet.title.length < 3 || packet.title.length > 50) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Title3-50Chars" });
        if (DEBUG_logAllFailedData) console.log("Title3-50Chars", packet);
        return;
    }
    if (packet.instructions && (packet.instructions.length > 4096)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Instructions4096Longer" });
        if (DEBUG_logAllFailedData) console.log("Instructions4096Longer", packet);
        return;
    }
    if (packet.notes && (packet.notes.length > 4096)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Notes4096Longer" });
        if (DEBUG_logAllFailedData) console.log("Notes4096Longer", packet);
        return;
    }

    if (CheckForIllegalWording(packet.title)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
        return;
    }
    if (packet.instructions && CheckForIllegalWording(packet.instructions)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
        return;
    }
    if (packet.notes && CheckForIllegalWording(packet.notes)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
        return;
    }

    // TODO: these should probably be required at some point
    if (packet.rating) {
        switch (packet.rating) {
            case 'e': // everyone
            case 'E': // everyone
            case 'd': // E+10 everyone above 10yo
            case 'D': // E+10 everyone above 10yo
            case 't': // teens
            case 'T': // teens
                break;
            default:
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "InvalidRating" });
                if (DEBUG_logAllFailedData) console.log("InvalidRating", packet);
                return;
        }
    }
    if (packet.restrictions && (!Array.isArray(packet.restrictions))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidRestrictionFormat" });
        if (DEBUG_logAllFailedData) console.log("InvalidRestrictionFormat", packet);
        return;
    }
    let nfe = false;
    if (packet.restrictions) {
        const usedRestrictions = [];
        for (const restriction of packet.restrictions) {
            switch (restriction) {
                case 'flash':
                case 'blood':
                case 'scary':
                    if (usedRestrictions.includes(restriction)) {
                        res.status(400);
                        res.header("Content-Type", 'application/json');
                        res.json({ "error": "CanOnlyUseRestrictionOnce" });
                        if (DEBUG_logAllFailedData) console.log("CanOnlyUseRestrictionOnce", packet);
                        return;
                    }
                    usedRestrictions.push(restriction);
                    break;
                case 'swear':
                    res.status(400);
                    res.header("Content-Type", 'application/json');
                    return res.json({ "error": "SwearingIsForbiddenOnSnailIDE" });
                default:
                    res.status(400);
                    res.header("Content-Type", 'application/json');
                    res.json({ "error": "InvalidRestriction" });
                    if (DEBUG_logAllFailedData) console.log("InvalidRestriction", packet);
                    return;
            }
        }
        if (usedRestrictions.includes('scary')) nfe = true;
    }
    const project = Cast.dataURLToBuffer(packet.project);
    if (!project) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    const zip = await safeZipParse(project);
    if (!zip) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    // DEBUG
    // fs.writeFile(`./cache/project.json`, await zip.file("project.json").async("string"), (err) => {
    //     if (err) console.error(err);
    // });
    if (!zip.file("project.json")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    const rawProjectCodeJSON = await zip.file("project.json").async("string");
    const projectCodeJSON = SafeJSONParse(rawProjectCodeJSON);
    if (!projectCodeJSON.meta) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    // ok yea project stuff exists
    // are we a low rank?
    const userRank = Cast.toNumber(UserManager.getProperty(packet.author, "rank"));
    if (userRank < 1) {
        if (projectCodeJSON.extensions) {
            // check extensions
            const isUrlExtension = (extId) => {
                if (!projectCodeJSON.extensionURLs) return false;
                return (extId in projectCodeJSON.extensionURLs);
            };
            for (let extension of projectCodeJSON.extensions) {
                let isUrl = isUrlExtension(extension);
                if (isUrl) {
                    extension = projectCodeJSON.extensionURLs[extension];
                }
                if (!checkExtensionIsAllowed(extension, isUrl)) {
                    res.status(403);
                    res.header("Content-Type", 'application/json');
                    res.json({ error: "CannotUseThisExtensionForThisRank", isUrl, extension });
                    if (DEBUG_logAllFailedData) console.log("CannotUseThisExtensionForThisRank", packet);
                    return;
                }
            }
        }
    }

    // set cooldown
    db.set(packet.author, Date.now() + 480000);

    // create project id
    db = new Database(`${__dirname}/data/projects/published.json`);
    let _id = Math.round(100000 + (Math.random() * 9999999999999));
    if (db.has(String(_id))) {
        while (db.has(String(_id))) _id++;
    }
    const id = _id;

    // we already checked earlier if this was a valid project
    fs.writeFile(`${__dirname}/data/projects/uploaded/p${id}.snail`, project, (err) => {
        if (err) console.error(err);
    });
    const image = Cast.dataURLToBuffer(packet.image);
    if (image) {
        fs.writeFile(`${__dirname}/data/projects/uploadedImages/p${id}.gif`, image, (err) => {
            if (err) console.error(err);
        });
    } else {
        fs.copyFile(`${__dirname}/cache/thumb.png`, `${__dirname}/data/projects/uploadedImages/p${id}.gif`, image, (err) => {
            if (err) console.error(err);
        });
    }

    // save in DB
    db.set(String(id), {
        id: id, // surprisingly this is useful to keep the id in the key named the id (unless my code is bad)
        name: packet.title,
        instructions: packet.instructions,
        notes: packet.notes,
        owner: packet.author,
        // we dont save image in the project anymore
        // image: packet.image, // base64 url
        // project: packet.project, // base64 url (not saved here since we save it in a file instead)
        featured: false, // if true, display it golden in pm or something idk
        accepted: true, // NO LONGER FALSE, used to be: must be accepted before it can appear on the public page

        remix: packet.remix,

        date: Date.now(), // set the creation date to now

        views: 0, // how many times the project file was grabbed in the api
        loves: [], // list of (encrypted) usernames who loved the project
        votes: [], // list of (encrypted) usernames who voted for the project to be featured

        rating: packet.rating, // E, E+10, T ratings (or ? for old projects)
        restrictions: packet.restrictions, // array of restrictions on this project (ex: blood, flashing lights)
    });

    // log for approvers
    // const body = JSON.stringify({
    //     content: `"${packet.title}" was uploaded by ${packet.author}`,
    //     embeds: [{
    //         title: `${packet.title} was uploaded`,
    //         color: 0x00bbff,
    //         fields: [
    //             {
    //                 name: "Owner",
    //                 value: `${packet.author}`
    //             },
    //             {
    //                 name: "ID",
    //                 value: `${id}`
    //             }
    //         ],
    //         author: {
    //             name: String(packet.author).substring(0, 50),
    //             icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.author).substring(0, 50)),
    //             url: String("https://penguinmod.com/profile?user=" + String(packet.author).substring(0, 50))
    //         },
    //         timestamp: new Date().toISOString()
    //     }]
    // });
    // fetch(process.env.ApproverLogWebhook, {
    //     method: "POST",
    //     headers: { "Content-Type": "application/json" },
    //     body: body
    // });

    // actually say the thing!!!!!!!!!!
    res.status(200);
    res.json({ "published": id });
    console.log(packet.title, "was published!");
});
// gets a published project
const viewsIpStorage = {};
app.get('/api/projects/getPublished', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const requestIp = req.ip;
    if ((req.query.id) == null) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NoIDSpecified" });
        return;
    }
    db = new Database(`${__dirname}/data/projects/published.json`);
    if (db.has(String(req.query.id))) {
        const project = db.get(String(req.query.id));
        if (String(req.query.type) == "file") {
            fs.readFile(`${__dirname}/data/projects/uploaded/p${project.id}.snail`, (err, data) => {
                if (err) {
                    res.status(500);
                    res.header("Content-Type", 'text/plain');
                    res.send(`<UnknownError err="${err}">`);
                    return;
                }
                if (typeof project.views !== "number") {
                    project.views = 0;
                }
                if (!Array.isArray(viewsIpStorage[Cast.toString(project.id)])) {
                    viewsIpStorage[Cast.toString(project.id)] = [];
                }
                const ipStorage = viewsIpStorage[Cast.toString(project.id)];
                if (!ipStorage.includes(requestIp)) {
                    project.views += 1;
                    ipStorage.push(requestIp);
                }
                db.set(String(req.query.id), project);
                res.status(200);
                res.header("Content-Type", 'application/x.scratch.sb3');
                res.send(data);
            });
            return;
        }
        const clone = structuredClone(project);
        clone.loves = Array.isArray(project.loves) ? project.loves.length : 0;
        clone.votes = Array.isArray(project.votes) ? project.votes.length : 0;
        res.status(200);
        res.json(clone);
    } else {
        res.status(404);
        res.json({ "error": "NotFound" });
    }
});
// sorts the projects into a nice array of pages
app.get('/api/projects/search', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const db = new Database(`${__dirname}/data/projects/published.json`);

    const projectOwnerRequired = req.query.user;
    const projectSearchingName = req.query.includes;
    const mustBeFeatured = req.query.featured;
    const sortingBy = Cast.toString(req.query.sortby);

    // add featured projects first but also sort them by date
    // to do that we just sort all projects then add them to a seperate array
    const featuredProjects = [];
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        const latestValue = sproject.date - project.date;
        if (sortingBy === 'likes') {
            return (sproject.loves || []).length - (project.loves || []).length;
        }
        if (sortingBy === 'votes') {
            return (sproject.votes || []).length - (project.votes || []).length;
        }
        if (sortingBy === 'views') {
            return (sproject.views || 0) - (project.views || 0);
        }
        return latestValue;
    }).filter(proj => proj.accepted === true).filter(project => {
        if (projectSearchingName) {
            const projectName = Cast.toString(project.name).toLowerCase().trim();
            const searchQueryName = Cast.toString(projectSearchingName).toLowerCase().trim();
            const tagMatches = searchQueryName.match(/#[^\s]+/gmi);
            let tagsFound = false;
            if (tagMatches) {
                const projectDescription = Cast.toString(project.instructions).toLowerCase().trim()
                    + ` ${Cast.toString(project.notes).toLowerCase().trim()}`;
                tagsFound = tagMatches.some(tag => projectDescription.includes(tag));
            }
            return tagsFound || projectName.includes(searchQueryName);
        }
        if (typeof projectOwnerRequired !== "string") {
            return true;
        }
        return project.owner === projectOwnerRequired;
    }).filter(project => {
        if (Cast.toString(mustBeFeatured) === 'exclude') {
            // returning here removes featured projects
            return project.featured != true;
        }
        if (project.featured) {
            featuredProjects.push(project);
        }
        if (Cast.toString(mustBeFeatured) === 'true') {
            // returning false here removes normal projects
            return false;
        }
        return project.featured != true;
    });
    // we set the array to featuredProjectsArray.concat(array) instead of array.concat(featuredProjectsArray)
    // because otherwise the featured projects would be after the normal projects
    const returnArray = featuredProjects.concat(projects);
    // make project list
    // new ProjectList() with .toJSON will automatically cut the pages for us
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page), null, !!projectOwnerRequired);
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
app.get('/api/getCommentsForProject', (req, res) => {
    const db = new Database(`${__dirname}` + "/projects/published" + ".json");
    if (!req.query.project) {
        res.status(400);
        res.send({ "error": "InvalidRequest" });
        return;
    }
    if (!db.has(req.query.project)) {
        res.status(404);
        res.send({ "error": "NotFound" });
        return;
    }
    let project = db.get(req.query.project);
    if (!project.comments) {
        db.set(req.query.projects, []);
        res.send({ "comments": [] });
        return;
    }
    res.send({ "comments": project.comments });
});
let commentspamratelimitthing = [];
async function checkProfanity(text) {
    let profanityList = Profanity;
    if (profanityList.length == 0) {
        profanityList = (await fetch("https://cdn.jsdelivr.net/gh/snguyenthanh/better_profanity@0.7.0/better_profanity/profanity_wordlist.txt").then(data => data.text())).split("\n")
        Profanity = profanityList;
    }
    profanityList.forEach(bleh => {
        if (String(text).toLowerCase().includes(bleh)) {
            return true;
        }
    });
    return false;
}
function getNewCommentId(type) {
    let db = new Database(`${__dirname}/data/commentcount.json`);
    db.add(type, 1);
    return db.get(type);
}
function getLastCommented(user) {
    let db = new Database(`${__dirname}/data/lastcommented.json`);
    return db.get(user);
}
function setLastCommented(user, cmt) {
    let db = new Database(`${__dirname}/data/lastcommented.json`);
    return db.set(user, cmt);
}
function getLastReplied(user) {
    let db = new Database(`${__dirname}/data/lastreplied.json`);
    return db.get(user);
}
function setLastReplied(user, cmt) {
    let db = new Database(`${__dirname}/data/lastreplied.json`);
    return db.set(user, cmt);
}
function addToRatelimit(ip) {
    let i = commentspamratelimitthing.length;
    commentspamratelimitthing.push(ip);
    setTimeout(() => {
        commentspamratelimitthing[i] = null;
    }, 10000);
}
//warning abysmal code no looking
app.post('/api/postComment', async (req, res) => {
    const db = new Database(`${__dirname}` + "/projects/published" + ".json");
    const packet = req.query;
    if (commentspamratelimitthing.includes(req.ip)) {
        res.status(429);
        res.send({ "error": "CommentRatelimit" });
        return;
    }
    if (UserManager.isBanned(packet.author)) {
        res.status(403);
        res.send({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.author, packet.passcode)) {
        res.status(400);
        res.send({ "error": "Reauthenticate" });
        if (DEBUG_logAllFailedData) console.log("Reauthenticate", packet);
        return;
    }
    if (UserManager.getProperty(packet.author, "rank") < 1) {
        res.status(403);
        res.send({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (!packet.content) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ "error": "InvalidRequest" });
        return;
    }
    if (!db.has(packet.project ?? "")) { // add ?? otherwise srever will crash :fail:
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ "error": "NotFound" });
        return;
    }
    let reply = false;
    if (packet.reply) {
        reply = true;
    }
    let filter = new Filter();
    let comments = db.get(packet.project).comments;
    if (!comments) {
        comments = [];
    }
    let projectauthor = db.get(packet.project).owner;
    if (getLastCommented(packet.author) === packet.content || (reply && getLastReplied(packet.author) === packet.content)) {
        res.status(429);
        res.header("Content-Type", "application/json");
        res.json({ "error": "Spam" });
        return;
    }
    if (reply) {
        if (!Array.isArray(comments)) {
            comments = [];
        }
        let foundcomment = false;
        let commentIndex = -1;
        for (let i = 0; i < comments.length; i++) {
            if (comments[i].id == packet.reply) {
                foundcomment = true;
                commentIndex = i;
                break;
            }
        }
        if (foundcomment) {
            let replies = comments[commentIndex].replies || [];
            replies.push({
                user: packet.author,
                text: filter.clean(packet.content),
                type: 'reply',
                id: getNewCommentId('reply')
            });
            comments[commentIndex].replies = replies;
            let newproject = db.get(packet.project);
            newproject.comments = comments;
            setLastReplied(packet.author, packet.content);
            db.set(packet.project, newproject);
            addToRatelimit(req.ip);
            res.header("Content-Type", "application/json");
            res.json({ "message": "success" });
            return;
        } else {
            res.status(404);
            res.header("Content-Type", "application/json");
            res.json({ "error": "ParentCommentNotFound" });
            return;
        }
    } else {
        let commentdata = {
            user: packet.author,
            text: filter.clean(packet.content),
            id: getNewCommentId('comments'),
            type: 'comment',
            replies: []
        };
        if (!Array.isArray(comments)) {
            comments = [];
        }
        comments.unshift(commentdata);
        console.log(comments[comments.length - 1]);
        UserManager.addMessage(projectauthor, {
            type: 'commentReceived',
            project: packet.project,
            user: packet.author,
            comment: commentdata
        });
        let newproject = db.get(packet.project);
        newproject.comments = comments;
        db.set(packet.project, newproject);
        addToRatelimit(req.ip);
        setLastCommented(packet.author, packet.content);
        res.header("Content-Type", "application/json");
        res.json({ "message": "success" });
    }
});
app.post('/api/deleteComment', async (req, res) => {
    const db = new Database(`${__dirname}` + "/projects/published" + ".json");
    const packet = req.query
    if (UserManager.isBanned(packet.author)) {
        res.status(403);
        res.send({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.author, packet.passcode)) {
        res.status(400);
        res.send({ "error": "Reauthenticate" });
        return;
    }
    if (!req.query.project) {
        res.status(400);
        res.send({ "error": "InvalidRequest" });
        return;
    }
    if (!db.has(req.query.project)) {
        res.status(400);
        res.send({ "error": "NotFound" });
        return;
    }
    if (!req.query.id) {
        res.status(400);
        res.send({ "error": "InvalidRequest" });
        return;
    }
    let project = db.get(req.query.project);
    let candeletecomment = req.query.author == project.owner;
    if (AdminAccountUsernames.get(req.query.author)) {
        candeletecomment = true;
    }
    let comments = project.comments;
    if (!comments) {
        comments = [];
    }
    let foundcomment = false;
    let i = -1;
    let foundtype = '';
    let commenti = 0;
    comments.map(comment => {
        if (comment.id == req.query.id) {
            foundcomment = true;
            foundtype = 'comment';
            commentExists = true;
            commenti = i;
            if (req.query.author == comment.user) {
                candeletecomment = true;
            }
        } else {
            if (comment.replies) {
                //try to see if its in replys
                let replies = comment.replies;
                if (!replies) {
                    replies = [];
                }

                let foundreply = false;
                let i2 = -1;
                replies.map(reply => {
                    if (reply.id == req.query.id) {
                        foundreply = true;
                    }
                    if (!foundreply) i2++;
                });

                if (foundreply) {
                    foundcomment = true;
                    foundtype = 'reply';
                    commenti = i;
                    i = i2;
                }
            }
        }
        if (!foundcomment) i++;
    });
    if (!foundcomment) {
        res.status(404);
        res.send({ "error": "NotFound" });
        return;
    }
    if (!candeletecomment) {
        res.status(403);
        res.send({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (foundtype == 'comment') {
        comments.splice(i, 1);
    } else {
        let comment = comments[commenti + 1];
        comment.replies.splice(i, 1);
        comments[commenti] = comment;
    }
    let newproject = db.get(req.query.project);
    newproject.comments = comments;
    db.set(req.query.project, newproject);
    res.send({ "message": "success" });
});

app.listen(port, () => console.log('Started server on port ' + port));
