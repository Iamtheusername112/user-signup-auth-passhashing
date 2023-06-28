// routes/auth.routes.js
const User = require("../models/User.model");

const { Router } = require("express");
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

const router = new Router();

// GET route ==> to display the signup form to users

router.get("/signup", (req, res) => res.render("auth/signup"));

// user profile route
router.get("/userProfile", (req, res) => res.render("users/user-profile"));

// POST route ==> to process form data
router.post("/signup", (req, res, next) => {
  //   console.log("The form data:", req.body);

  const { username, email, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        // username: username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        passwordHash: hashedPassword,
      });
    })
    .then((userFromDB) => {
      //   console.log("Newly created user is: ", userFromDB);
      res.redirect("/userProfile");
    })
    .catch((error) => next(error));
});
module.exports = router;
