const express = require('express');
const cors = require('cors');
const ejs = require('ejs');
const app = express();
const morgan = require("morgan");
require("dotenv").config();
require("./config/database");
const User = require ("./models/user.model")
require("./config/passport")

//1 for password encryption
const bcrypt = require('bcrypt');
const saltRounds = 10;

//1.1 to save session in database
const session = require('express-session');
const MongoStore = require('connect-mongo'); //to store session


//1.2 to authenticate the user with password
const passport = require('passport');    


app.set("view engine", "ejs");
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(morgan("dev"));

//code from API documentation for seeson store
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URL,
    collectionName: "sessions",
  })
 // cookie: { secure: true }
}))

app.use(passport.initialize()) //to initialize passport when call to route
app.use(passport.session()) //to use the session for authentication


//base URL
app.get("/", (req, res)=>{
    res.render("index");        //using render as it is related to ejs
});

//register : get data from form
app.get("/register", (req, res)=>{
    res.render("register");        
});

//register : post to handle user data
app.post("/register", async (req, res)=>{
    try{
        const user = await User.findOne({username: req.body.username});
        if(user) return res.status(201).send("User is already registered");
        
        //encrypting password
        bcrypt.hash(req.body.password, saltRounds, async function(err, hash) {
            const newUser = new User({
                username: req.body.username,
                //here req.body.password is sent to becrypt and hash is placed in return
                password : hash  
            });
            await newUser.save();
            res.status(201).redirect("/login");
            // Store hash in your password DB.
        });
    }


    catch(error){
        res.status(500).send(error.message)};
});

//checking login status
const checkLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) {
      return res.redirect("/profile");
    }
    next();
  };
  
  // login : get
  app.get("/login", checkLoggedIn, (req, res) => {
    res.render("login");
  });
  
  // login : post
  app.post(
    "/login",
    passport.authenticate("local", {
      failureRedirect: "/login",
      successRedirect: "/profile",
    })
  );
  
  const checkAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/login");
  };
  
  // profile protected route
  app.get("/profile", checkAuthenticated, (req, res) => {
    res.render("profile");
  });
  

//logout route
app.get("/logout", (req, res) => {
    try {
      req.logout((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  });

module.exports = app;