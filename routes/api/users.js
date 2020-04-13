const express = require("express");
const router = express.Router();
const { check, validationResult } = require("express-validator");
const User = require("../../models/User");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");

// @route   POST api/users
// @desc    Register User
// @access  Public
router.post(
    "/",
    [
        check("name", "Name is required").not().isEmpty(),
        check("email", "Please include a valid email").isEmail(),
        check("password", "Passwords must be 6 or more characters").isLength({
            min: 6,
        }),
    ],

    async (req, res) => {
        const errors = validationResult(req);

        //check for errors
        if (!errors.isEmpty()) {
            //sends back error message from checks
            return res.status(400).json({ errors: errors.array() });
        }

        //Destructure the body request
        const { name, email, password } = req.body;

        try {
            //See if user exists
            let user = await User.findOne({ email });

            //send error status if user does exist
            if (user) {
                res.status(400).json({
                    errors: [{ msg: "User already exists" }],
                });
            }

            //Get users gravatar
            const avatar = gravatar.url(email, {
                //size
                s: "200",
                //rating
                r: "pg",
                //default img
                d: "mm",
            });

            //create instance of a new user (unsaved)
            user = new User({
                name,
                email,
                avatar,
                password,
            });

            //Encrypt password using bcrypt
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            //save user to db
            await user.save();

            //Return the json webtoken
            res.send("User route");
        } catch (err) {
            console.error(err.message);
            res.status(500).send("Server Error");
        }
    }
);

module.exports = router;
