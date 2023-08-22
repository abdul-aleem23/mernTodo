import express from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jsonWebToken  from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// initializing express
const app = express();
const PORT = 5000;
// initializing mongoDB
mongoose.connect("mongodb://localhost:27017", {
    dbname: "backend"
})
.then((x) => console.log("Database connected successfully"))
.catch((e) => console.log(e))

// creating the Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
})
const User = mongoose.model("User", userSchema); 

// middle-ware
app.use(express.static((path.join(path.resolve(), "public")))); 
app.use(express.urlencoded( {extended: true} )) 
app.use(cookieParser());

// setting up View Engine [res.render() uses this]
app.set("view engine", "ejs");

app.listen(PORT, () => {
    console.log(`Server is running on port: ${PORT}`);
});


const isAuthenticated = async (req, res, next) => {
    const {token} = req.cookies;
    if(token){

        const decodedUserId = jsonWebToken.verify(token, "tgvbhyujnmki");

        req.user = await User.findById(decodedUserId._id)
        next()
    }
    else {
        res.redirect("login");
    }
}

//API's
app.get("/",isAuthenticated, (req, res) => {
    res.render("logout", {name: req.user.name})
});

// login
app.get("/login", (req, res) => {
    res.render("login");
});

//register 
app.get("/register", (req, res) => {
    res.render("register");
});

// logout [keeping it a get request bc unlike login we do not have to post anything like email pass ]
app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly:true,
        expires:new Date(Date.now()),
    });
    res.redirect("/");
});

// login post request
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    let user = await User.findOne({ email });
    if (!user) return res.redirect("register");
    
    //bc we already hashed the password before saving in db, we will convert the entered password to hash, in order to compare both.
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) return res.render("login", { email, message: "Incorrect Password" });

    const token = jsonWebToken.sign({ _id:user._id }, "tgvbhyujnmki");

    res.cookie("token", token, {
        httpOnly:true,
        expires:new Date(Date.now()+60*1000),
    });
    res.redirect("/");

});

// register post request
app.post("/register", async (req, res) => {
    const {name,email, password} = req.body;

    let user = await User.findOne({ email });
    if (user){
        return res.redirect("/login");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user = await User.create({
        name,
        email,
        password: hashedPassword,
    });

    const token = jsonWebToken.sign({ _id:user._id }, "tgvbhyujnmki");

    res.cookie("token", token, {
        httpOnly:true,
        expires:new Date(Date.now()+60*1000),
    });
    res.redirect("/");

});
