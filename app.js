const express = require('express');
const cors = require('cors');
const ejs = require('ejs');
const app = express();
const morgan = require("morgan");
require("./config/database");
const User = require ("./models/user.model")

//1 for password encryption
const bcrypt = require('bcrypt');
const saltRounds = 10;

//1.1 to save session in database
var session = require('express-session')

//1.2 to authenticate the user with password
const passport = require('passport');    


app.set("view engine", "ejs");
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(morgan("dev"));

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

//login : get to return login page
app.get("/login", (req, res)=>{
    res.render("login");        
});

//login : post to handle user data after submitting login information
app.post("/login", (req, res)=>{
    try{
        res.status(200).send("login successfully");
    }
    catch(error){
        res.status(500).send(error.message);
    };  
});


//profie: protected route
app.get("/profile", (req, res)=>{
    res.render("profile"); 
});  

//logout rout
app.get("/logout", (req, res)=>{
    res.redirect("/"); 
});  

module.exports = app;