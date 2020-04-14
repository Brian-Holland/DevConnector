const express = require("express");
const router = express.Router();
const auth = require("../../middleware/auth");
const User = require("../../models/User");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get("/", auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// @route   POST api/auth
// @desc    Authenticate user and get token
// @access  Public
router.post(
    "/",
    [
        check("email", "Please include a valid email").isEmail(),
        check("password", "Password is required").exists(),
    ],

    async (req, res) => {
        const errors = validationResult(req);

        //check for errors
        if (!errors.isEmpty()) {
            //sends back error message from checks
            return res.status(400).json({ errors: errors.array() });
        }

        //Destructure the body request
        const { email, password } = req.body;

        try {
            //See if user exists
            let user = await User.findOne({ email });

            //send error status if user does not exist
            if (!user) {
                return res.status(400).json({
                    errors: [{ msg: "Invalid credientials" }],
                });
            }

            //compare plain text password vs encrypted password
            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({
                    errors: [{ msg: "Invalid credientials" }],
                });
            }

            //Return the json webtoken
            const payload = {
                user: {
                    id: user.id,
                },
            };

            jwt.sign(
                payload,
                //use the secret from the config file
                config.get("jwtSecret"),
                //set expiration to 1 hour
                { expiresIn: 3600 },
                (err, token) => {
                    //throw error if error
                    if (err) throw err;
                    //send token back to client
                    res.json({ token });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).send("Server Error");
        }
    }
);

module.exports = router;
