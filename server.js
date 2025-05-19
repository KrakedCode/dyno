require("dotenv").config()

//for cookies i believe 
const jwt = require("jsonwebtoken")
const cookieParser = require('cookie-parser')
//for carousel
//const glider = require("glider")



//password encryption for storing in the database
const bcrypt = require("bcrypt")
const crypto = require("crypto")
//backend framework
const express = require("express")
//database package
const db = require("better-sqlite3")("data.db")
db.pragma("journal_mode = WAL")


// database management and setup
//function that creates tables in the database

const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL,
        level INTEGER NOT NULL,
        attemptedClimbs INTEGER,
        completedClimbs INTEGER,
        bestCompletedClimb INTEGER,
        flashes INTEGER
        )
        `).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS climbs (
        difficulty INTEGER NOT NULL,
        attempts INTEGER NOT NULL,
        user INTEGER NOT NULL,
        FOREIGN KEY (user) REFERENCES users (id)
        )`).run()
    
    db.prepare(`
        CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) NOT NULL,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
        )`).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
        )`).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        title STRING NOT NULL,
        progress INTEGER DEFAULT 0,
        goal INTEGER NOT NULL,
        category STRING NOT NULL,
        userid INTEGER NOT NULL,
        FOREIGN KEY (userid) REFERENCES users(id) 
        )`).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        expiry INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
        )`).run()
    
})

createTables()


//create an instance of express
const app = express()

//setup the app to view ejs extensions
app.set("view engine", "ejs")

//??? need to learn more
app.use(express.urlencoded({extended: false}))

//connect server to css files
app.use("/public", express.static("public"))

//parse cookies i guess
app.use(cookieParser())

//functions 

function updateUser(req,res) {
    //attempted climbs
    const sumOfAttemptedClimbsStatement = db.prepare(`SELECT SUM(attempts) AS total FROM climbs WHERE user = ?`).get(req.user.userid).total

//flashes
    const flashStatement = db.prepare(`SELECT COUNT(*) AS count FROM climbs WHERE user = ? AND attempts =1`).get(req.user.userid).count

//completed climbs
    const completedClimbStatement = db.prepare(`SELECT COUNT(*) AS count FROM climbs WHERE user =?`).get(req.user.userid).count

//best completed climbs 
    const bestCompletedClimbStatement = db.prepare(`SELECT MAX(difficulty) AS max FROM climbs WHERE user = ?`).get(req.user.userid).max




    //update the user table 
    const updateUserTableStatement = db.prepare(`UPDATE users SET attemptedClimbs = ?, flashes = ?, completedClimbs = ?, bestCompletedClimb = ? WHERE id = ?`)

    updateUserTableStatement.run(sumOfAttemptedClimbsStatement, flashStatement, completedClimbStatement, bestCompletedClimbStatement, req.user.userid)
}
function updateCookie(req,res) {
    

    
    const updatedUser = db.prepare(`SELECT * FROM users WHERE id = ?`).get(req.user.userid)

    res.clearCookie("ClimbPros")
    //sign in with cookie
    const ourTokenValue = jwt.sign(
    {exp: Math.floor(Date.now() /1000) + 60 * 60 * 24,
            userid: updatedUser.id,
            username: updatedUser.username,
            climbs: updatedUser.attemptedClimbs,
            topOuts: updatedUser.completedClimbs,
            best: updatedUser.bestCompletedClimb,
            flash: updatedUser.flashes },
        process.env.JWTSECRET
    )

    res.cookie("ClimbPros", ourTokenValue, {
        httpOnly:true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000* 60 * 60 * 24
    })
}

function securedUser(req,res,next) {
    console.log("entered secured user")

    if(req.user && req.user.userid){
        next()

    }else{
        return res.render("login")
    }
}


  
//middleware
app.use(function (req,res,next) {
    res.locals.errors = []
    res.locals.status = ""

    //try to decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.ClimbPros, process.env.JWTSECRET)
        req.user = decoded
    } catch(err) {
        console.log("problem in decoding cookie")
        req.user = false
    }

    res.locals.user = req.user
    console.log(req.user)
    /*
    const ua = req.headers['user-agent'] || '';
    const isMobile = /android|iphone|ipad|ipod|mobile/i.test(ua);
    res.locals.isMobile = isMobile;

    console.log('User-Agent:', ua);
    console.log('Mobile detected:', isMobile);
    */
    next()
})
//get requests
app.get("/", (req,res) => {
    console.log(req.user)
    if(!req.user){
        

        return res.render("homepage")
    }

    if(req.user.skycolor){
        return res.render("introduction")
    }

    return res.render("dashboard")
        
    
    
})

app.get("/intro-complete", (req,res) => {
    //remove skycolor tag
    if(req.user){
        const updatedPayload = {...req.user}
        delete updatedPayload.skycolor
        
        //sign a new cookie
        const newToken = jwt.sign(updatedPayload,process.env.JWTSECRET)
        
        
        //set the new token as a cookie
        res.cookie("ClimbPros", newToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24
        },)
    }

    return res.redirect("/")
})



app.get("/goals", securedUser, (req,res) => {
    const userGoalStatement = db.prepare(`SELECT * FROM goals WHERE userid =?`)
    const goals = userGoalStatement.all(req.user.userid)
    /*
    const isMobile = res.locals.isMobile
    const minGoals = isMobile ? 3 : 6 

    res.render("goals", {goals,isMobile, minGoals})

    */

    res.render("goals", {goals})
})

app.get("/community", securedUser, (req,res) => {
    
    
    
    const userID = req.user.userid

    const friends = db.prepare(`
        SELECT u.id, u.username, 
            (SELECT COUNT(*) FROM messages
             WHERE sender_id = u.id AND receiver_id = ? AND read = 0
            ) AS unreadCount
        FROM users u
        JOIN friends f
            ON (
            (f.sender_id = ? AND f.receiver_id = u.id) OR
            (f.receiver_id = ? AND f.sender_id = u.id)
            ) 
            WHERE f.status = 'accepted'
        `).all(userID,userID,userID)

     const pendingRequests = db.prepare(`
        SELECT f.id, u.username AS senderUsername
        FROM friends f JOIN users u 
        ON f.sender_id = u.id 
        WHERE f.receiver_id = ? AND f.status = 'pending'
        `).all(userID)
    
    const sentRequests = db.prepare(`
        SELECT f.id, u.username AS receiverUsername
        FROM users u JOIN friends f
        ON  f.receiver_id = u.id
        WHERE f.sender_id = ? AND f.status = 'pending'
        `).all(userID)
    
        res.render("community", {friends,pendingRequests, sentRequests})
})

app.get("/messages/:username", securedUser, (req,res) => {
    
    const currentUserID = req.user.userid
    const friendUsername = req.params.username
console.log("This is exactly what i am looking for", friendUsername)
    const friendRow = db.prepare(`SELECT id FROM users WHERE username =?`).get(friendUsername)
    if (!friendRow) {
        return res.status(404).send("User not found");
      }
    const friendID = friendRow.id

    const messages = db.prepare(`
        SELECT m.*, u.username AS senderName
        FROM messages m
        JOIN users u
        ON m.sender_id = u.id
        WHERE (sender_id = ? AND receiver_id = ?)
            OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
        `).all(currentUserID,friendID,friendID,currentUserID)
    
    db.prepare(`
        UPDATE messages
        SET read = 1
        WHERE receiver_id = ? AND sender_id = ? AND read = 0
        `).run(currentUserID,friendID)

        const friend = db.prepare(`SELECT id, username FROM users WHERE id=?`).get(friendID);

    res.render("messages", {friend,messages,currentUserID: req.user.userid})
})

app.get("/leaderboard", (req, res) => {
    

    let leaderboard = [];
    const filter = req.query.filter || 'difficulty'
    const order = req.query.order || 'descending'

    if (filter === "difficulty") {
        leaderboard = db.prepare(`SELECT * FROM users ORDER BY bestCompletedClimb ${order === 'descending' ? 'DESC' : 'ASC'}`).all()
    } else if (filter === "climbs") {
        leaderboard = db.prepare(`SELECT * FROM users ORDER BY attemptedClimbs ${order === 'descending' ? 'DESC' : 'ASC'}`).all()
    } else if (filter === "topouts") {
        leaderboard = db.prepare(`SELECT * FROM users ORDER BY completedClimbs ${order === 'descending' ? 'DESC' : 'ASC'}`).all()
    } else if (filter === "flashes") {
        leaderboard = db.prepare(`SELECT * FROM users ORDER BY flashes ${order === 'descending' ? 'DESC' : 'ASC'}`).all()
    }

    res.render("leaderboard", {
        leaderboard,
        filter,
        order
    })
})


app.get("/submit-climb", securedUser, (req, res) => {
       

    res.render("submit-climb")
})

app.get("/login", (req, res) => {
res.render("login")
})

app.get("/password", (req,res) => {
    res.render("password")
})

app.get("/reset-password/:token", (req,res) => {
    console.log("hello")
    const tokenRow = db.prepare(`SELECT * FROM reset_tokens WHERE token = ?`)
    .get(req.params.token)

    if(!tokenRow || tokenRow.expiry < Date.now()) {
        db.prepare(`DELETE FROM reset_tokens WHERE token = ?`).run(tokenRow.token)
        return res.send("Invalid or expired session.")
    }

    res.render("reset-password", {token: req.params.token})
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/logout", (req, res) => {
    res.clearCookie("ClimbPros")
    res.redirect("/")
})

//post requests
app.post("/register", (req, res) => {
    let errors = []
    
    if (typeof(req.body.username) !== "string") req.body.username = ""
    if (typeof(req.body.password) !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()   

    //username checks
    if (!req.body.username) errors.push("You must provide a username")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters long")
    if (req.body.username && req.body.username.length > 20) errors.push("Username must not exceed 20 characters")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]/)) errors.push("Username cannot contain special characters")

   //password checks
    if (!req.body.password) errors.push("You must provide a password")
    if (req.body.password && req.body.password.length < 3) errors.push("Password must be at least 3 characters long")
    if (req.body.password && req.body.password.length > 100) errors.push("Password must not exceed 100 characters")     
    
    //check if username exists
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)

    //if exists push error message 
    if (usernameCheck) errors.push("That username is already taken")
    

    if(errors.length) {
        return res.render("register", {errors} )
    } 

    //password encryption
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    //enter user into database

    const ourStatement = db.prepare("INSERT INTO users (username, password, level, attemptedClimbs, completedClimbs, bestCompletedClimb, flashes) VALUES (?, ?, 1, 0, 0, 0, 0)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookUpStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookUpStatement.get(result.lastInsertRowid)
    
    //cookie time
    const ourTokenValue = jwt.sign(
        {exp: Math.floor(Date.now() /1000) + 60 * 60 * 24, skycolor: "blue", userid: ourUser.id, username: ourUser.username, climbs: ourUser.attemptedClimbs, topOuts: ourUser.completedClimbs, best: ourUser.bestCompletedClimb, flash: ourUser.flashes },
        process.env.JWTSECRET
    )

    res.cookie("ClimbPros", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    console.log(req.user)
    res.redirect("/")
    console.log(req.user)

})

app.post("/login", (req, res) => {
    let errors = []
    let numberOfErrors = 0
    if(typeof(req.body.username) !== "string") req.body.username = ""
    if(typeof(req.body.password) !== "string") req.body.password = ""

    if(req.body.username.trim() == "") numberOfErrors++
    if(req.body.password == "") numberOfErrors++

    //username checks
    if (!req.body.username) numberOfErrors++
    if (req.body.username && req.body.username.length < 3) numberOfErrors++
    if (req.body.username && req.body.username.length > 10) numberOfErrors++
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) numberOfErrors++
    
    //password checks
    if (!req.body.password) numberOfErrors++
    if (req.body.password && req.body.password.length < 3) numberOfErrors++
    if (req.body.password && req.body.password.length > 10) numberOfErrors++
    
    //if impossible username/password dont bother checking database
    if (numberOfErrors > 0) {
        errors = ["You must provide a valid Username/Password"]
        return res.render("login", {errors})
    }

    //check database for user
    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if(!userInQuestion){
        errors = ["Incorrect Username/Password"]
        return res.render("login", {errors})
    }

    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot){
        errors = ["Incorrect Username/Password"]
        return res.render("login", {errors})
    }
    
    //sign in with cookie
    const ourTokenValue = jwt.sign(
        {exp: Math.floor(Date.now() /1000) + 60 * 60 * 24, userid: userInQuestion.id, username: userInQuestion.username, climbs: userInQuestion.attemptedClimbs, topOuts: userInQuestion.completedClimbs, best: userInQuestion.bestCompletedClimb, flash: userInQuestion.flashes },
        process.env.JWTSECRET
    )

    res.cookie("ClimbPros", ourTokenValue, {
        httpOnly:true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000* 60 * 60 * 24
    })

    res.redirect("/")
})

app.post("/forgot-password" , (req,res) => {
    let errors = []
    const username = req.body.username

    const usernameStatement = db.prepare(`SELECT * FROM users WHERE username = ?`)
    const userInQuestion = usernameStatement.get(username)
    if(!userInQuestion){
        errors.push("username not found")
        return res.render("password" , {errors})
    }

    const token = crypto.randomBytes(32).toString("hex")
    const expiry = Date.now() + 300000 // 5min

    db.prepare(`INSERT INTO reset_tokens (user_id, token, expiry) VALUEs (?,?,?)`)
        .run(userInQuestion.id, token, expiry)

        const link = `http://localhost:3000/reset-password/${token}`;

  res.send(`Password reset link: <a href="${link}">${link}</a>`)


})

app.post("/reset-password/:token", async (req,res) => {
    const tokenRow = db.prepare("SELECT * FROM reset_tokens WHERE token = ?").get(req.params.token);

    if (!tokenRow || tokenRow.expiry < Date.now()) {
      return res.send("Invalid or expired session.");
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    db.prepare(`UPDATE users SET password = ? WHERE id = ?`).run(hashedPassword, tokenRow.user_id)
    db.prepare(`DELETE FROM reset_tokens WHERE token = ?`).run(req.params.token)

    res.redirect("/login")
})

app.post("/checkSignIn" , (req, res) => {
    let status = ""
    if(req.user){
        status = "signed in"
    } else{
        status = "not signed in"
    }
    console.log(status)
    return res.redirect("/")
})

app.post("/submitClimb" ,securedUser,  (req,res) => {
    //logic error
    let errors = []
    if(req.body.difficulty > 10 || req.body.difficulty < 0){
        errors.push("Press X to Doubt")
        return res.render("submit-climb", {errors})
    }
    const climbStatement = db.prepare(`INSERT INTO climbs (difficulty, attempts, user) VALUES (?, ?, ?) `)
    climbStatement.run(req.body.difficulty, req.body.attempts, req.user.userid)
    
    updateUser(req,res)
    //cookie time
    updateCookie(req,res)

    //update goals table
    
    const goals = db.prepare(`SELECT * FROM goals WHERE userid = ?`).all(req.user.userid)

    for( const goal of goals) {
    
        let increment = 0

        switch (goal.category) {
            case "climbs":
                increment = req.body.attempts
                break
            case "flashes":
                if(req.body.attempts == 1) increment = 1
                break
            case "topouts":
                increment = 1
                break
            case "difficulty":
                if(req.body.difficulty > goal.progress){
                    db.prepare(`UPDATE goals SET progress = ? WHERE id =?`)
                    .run(req.body.difficulty,goal.id)
                    const updatedProgress = db.prepare(`SELECT * from goals WHERE id = ?`).get(goal.id)

                    if(updatedProgress.progress >= goal.goal){
                        db.prepare(`DELETE FROM goals WHERE id = ?`).run(goal.id)
                    }
                    continue
                }
                break
            default:
                console.warn(`Unknown goal category: ${goal.category}`)
                continue
            
        }
        console.log("Attempts = ", req.body.attemps)
        if(increment > 0){

    
         db.prepare(`
            UPDATE goals
            SET progress = progress + ?
            WHERE id = ?
            `).run(increment,goal.id)

        }
        
    const updatedProgress = db.prepare(`SELECT * from goals WHERE id = ?`).get(goal.id)
    if(updatedProgress.progress >= goal.goal){
        db.prepare(`DELETE FROM goals WHERE id = ?`).run(goal.id)
    }
} 
    

    

    
    res.redirect("/")
})

app.post("/delete-recent-climb",securedUser, async (req,res) => {
    const userId = req.user.userid

        const recentClimb = db.prepare(`
            SELECT rowid FROM climbs
            WHERE user = ?
            ORDER BY rowid DESC
            LIMIT 1
            `).get(userId)

            if(recentClimb){
                db.prepare(`
                    DELETE FROM climbs 
                    WHERE rowid = ?
                    `).run(recentClimb.rowid)
            }

            updateUser(req,res)
            updateCookie(req,res)
        res.redirect("/")
})

app.post("/updateStats",securedUser,  (req,res) => {
    
    let errors = []
    if(req.body.difficulty > 10 || req.body.difficulty < 0){
        errors.push("Press X to Doubt")
        return res.render("dashboard", {errors})
    }

    const updatedStatement = db.prepare(`
        UPDATE users 
        SET attemptedClimbs = ?, 
            completedClimbs = ?, 
            bestCompletedClimb = ?, 
            flashes =? 
        WHERE id = ?
        `)
    
        updatedStatement.run(req.body.climbs, req.body.topOut, req.body.difficulty, req.body.flashed, req.user.userid)

    updateCookie(req,res)


    db.prepare(`DELETE FROM climbs WHERE user = ?`).run(req.user.userid)
    res.redirect("/")
})

app.post("/friends/request", securedUser, (req,res) => {
    const senderID = req.user.userid
    const receiverUsername = req.body.receiverUsername.trim()

    const friends = db.prepare(`
        SELECT u.id, u.username, 
            (SELECT COUNT(*) FROM messages
             WHERE sender_id = u.id AND receiver_id = ? AND read = 0
            ) AS unreadCount
        FROM users u
        JOIN friends f
            ON (
            (f.sender_id = ? AND f.receiver_id = u.id) OR
            (f.receiver_id = ? AND f.sender_id = u.id)
            ) 
            WHERE f.status = 'accepted'
        `).all(senderID,senderID,senderID)

     const pendingRequests = db.prepare(`
        SELECT f.id, u.username AS senderUsername
        FROM friends f JOIN users u 
        ON f.sender_id = u.id 
        WHERE f.receiver_id = ? AND f.status = 'pending'
        `).all(senderID)
    
    const sentRequests = db.prepare(`
        SELECT f.id, u.username AS receiverUsername
        FROM users u JOIN friends f
        ON  f.receiver_id = u.id
        WHERE f.sender_id = ? AND f.status = 'pending'
        `).all(senderID)
    

    const userCheck = db.prepare(`SELECT id FROM users WHERE username = ?`).get(receiverUsername)
    let status = []
    if(!userCheck){
        status = ["user does not exist"]
        console.log("user does not exist")
        return res.render("community",{
            status,
            friends,
            pendingRequests,
            sentRequests})
    } 

    if(userCheck.id === senderID){
        status = ["I wish I was friends with myself too"]
        console.log("I wish I was friends with myself too")
        return res.render("community", {
            status,
            friends,
            pendingRequests,
            sentRequests
        })
    }
    
    const receiverID = userCheck.id

    //prevent duplicate requests
    const existing = db.prepare(`
        SELECT * 
        FROM friends 
        WHERE 
            (sender_id = ? AND receiver_id = ?) OR
            (sender_id = ? AND receiver_id = ?)
            `).get(senderID,receiverID, receiverID, senderID)
        
        if(!existing) {
            db.prepare(`
                INSERT INTO friends 
                (sender_id, receiver_id, status) 
                VALUES (?,?, 'pending')
            `).run(senderID,receiverID)
            console.log("friend request sent")
        }
    
    res.redirect("/community")
})

app.post("/friends/accept",securedUser,  (req,res) => {
    const requestID = req.body.requestID
    const receiverID = req.user.userid

    
    db.prepare(`
        UPDATE friends
        SET status = 'accepted'
        WHERE id =? AND receiver_id = ?
        `).run(requestID,receiverID)

    res.redirect("/community")
})

app.post("/friends/decline",securedUser,  (req,res) => {
    const requestID = req.body.requestID
    const receiverID = req.user.userid

    db.prepare(`
        DELETE FROM friends 
        WHERE 
          (sender_id = ? AND receiver_id = ?) 
          OR 
          (receiver_id = ? AND sender_id = ?)
      `).run(requestID, receiverID, requestID, receiverID);
    
    res.redirect("/community")
})

app.post("/friends/cancel", securedUser, (req,res) => {
    const requestID =req.body.requestID
     
    db.prepare(`DELETE FROM friends WHERE id = ?`).run(requestID)
    
    res.redirect("/community")
})

app.post("/messages/:username",securedUser,  (req,res) => {
    const senderID = req.user.userid
    const receiverUsername= req.params.username
    const messageText = req.body.message

    const receiverRow = db.prepare(`SELECT id FROM users WHERE username =?`).get(receiverUsername)
    if (!receiverRow) {
        return res.status(404).send(receiverRow);
      }
    const receiverID = receiverRow.id
    //stops empty messages from being sent
    if(!messageText.trim()) {
        return res.redirect(`/messages/${receiverID}`)
    }
    db.prepare(`
        INSERT INTO MESSAGES (sender_id, receiver_id, message, read)
        VALUES (?,?,?,0)
        `).run(senderID,receiverID,messageText)

    
    return res.redirect(`/messages/${receiverUsername}`)
})

app.post("/submit-Goal", securedUser, (req,res) => {

    const goalStatement = db.prepare(`INSERT INTO goals (title, progress,goal,category , userid) VALUES (?,0,?,?,?)`)
    goalStatement.run(req.body.title, req.body.goal, req.body.category, req.user.userid )
    
    return res.redirect("/goals")
})




app.listen(300)
