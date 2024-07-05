const Router = require("express").Router;
const router = new Router();
const jwt = require("jsonwebtoken");

const ExpressError = require("../expressError");
const User = require('../models/user');
const {SECRET_KEY} = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async function (req, res, next) {
    try { //authenticate user, create JWT and return the token
        const { username, password } = req.body;
        if (!username || !password) {
            throw new ExpressError ('Username and password required.', 400);
        }

        if ( await User.authenticate(username, password)) {
            const token  = jwt.sign({ username }, SECRET_KEY);
            User.updateLoginTimestamp(username);
            return res.json({ token });
        }
        throw new ExpressError("Invalid user/password", 400);
    } catch (err) {
        if (err.code === '23505') {
            return next (new ExpressError('Username taken. Please pick another!', 400));
        }
        return next(err);
    }
});


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
    try {// register new user, creat JWT, and return the token
        const newUser = await User.register(req.body);
        const username = newUser.username;
        const token  = jwt.sign({ username }, SECRET_KEY);

        User.updateLoginTimestamp(username);

        return res.json({token});
    } catch (err) {
        return next(err);
    }
});


module.exports = router;