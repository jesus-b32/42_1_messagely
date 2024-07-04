/** Common config for message.ly */

// read .env files and make environmental variables

// require("dotenv").config();
require('@dotenvx/dotenvx').config();

const DB_URI = (process.env.NODE_ENV === "test")
  ? process.env.DATABASE_TEST_URL
  : process.env.DATABASE_URL;

const SECRET_KEY = process.env.SECRET_KEY || "secret";

const BCRYPT_WORK_FACTOR = 12;


module.exports = {
  DB_URI,
  SECRET_KEY,
  BCRYPT_WORK_FACTOR,
};