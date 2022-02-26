require('dotenv').config()
const express=require("express");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy=require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app=express();


app.use(express.urlencoded({extended:true}));
app.set("view engine","ejs");
app.use(express.static("public"));

//INITALIZING SESSIONS PACKAGE
app.use(session({
    secret:"it is a secret",
    resave:false,
    saveUninitialized:false,
   
}))
//INITIALIZING PASSPORT PACKAGE
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
//MONGODB  SCHEMA
const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    username:String,
    
    secret:String
    
});
//for a schema if it has to be a pluggin it must be an mongoose schema

//passportLocalMongoose is used for hasing and salting ans use to store our data into data base
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User =mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

//INCLUDING GOOGLE STRATEGY
passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets" 
},
  function(accessToken, refreshToken, profile , cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id ,username:profile.displayName}, function (err, user) {
      return cb(err, user);
    });
  }
));
//INCLUDING THE FACEBOOK STRATEGY

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({facebookId: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/",function(req,res){
    res.render("home");
});
//INITIATE AUTHENTICATE WITH  THE GOOGLE
app.get("/auth/google",
    passport.authenticate("google",{scope:["profile"]})

);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


  //INITIATE AUTHENTICATE USING FACEBOOK

  app.get('/auth/facebook',
      passport.authenticate("facebook", { scope : ['public_profile'] })

 
  );

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets
    res.redirect('/secrets');
  });  


app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});



//SECRETS PAGE
app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}},function(err,foundUsers){
        if (err){
            console.log(err);
        }
        else{
            if (foundUsers){
                res.render("secrets",{userWithSecrets: foundUsers});

            }
            
        }
    });

});
app.get("/submit",function(req,res){
    if (req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/");
    }

      
});

app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;
    User.findById(req.user.id,function(err,foundUser){
        if (err){
            console.log(err);

        }else{
            if (foundUser){
                foundUser.secret=submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }

        }



    });
    // res.render('secrets',{data:content});
});
app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
})
app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
        if (err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });


    
  

});

app.post("/login",function(req,res){
    const user=new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,function(err){
        if (err){
            console.log(err);
            res.redirect("/login");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");

            });
           
        }
    });



});













app.listen(3000,function(){
    console.log("server started");
})













