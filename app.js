const express = require('express');
const cors = require('cors');
const ejs = require('ejs');
const app = express();
const morgan = require("morgan")
app.use(morgan("combined"));
require("./config/database");

app.set("view engine", "ejs");
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//base URL
app.get("/", (req, res)=>{
    res.render("index");        //using render as it is related to ejs
});

//register : get data from form
app.get("/register", (req, res)=>{
    res.render("register");        
});

//register : post to handle user data
app.post("/register", (req, res)=>{
    try{
        res.status(201).send("User is created successfully");
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