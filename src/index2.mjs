import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import User from "./Database/Schema/userSchema.mjs";
import { hashPassword } from "./utils/hashPassword.mjs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { isAuthenticated } from "./utils/authentication.mjs";

dotenv.config();

mongoose
  .connect(process.env.MONGO_DB_URL)
  .then(() => console.log("Database connected"))
  .catch((err) => console.log(err));

const app = express();
app.use(express.json());
app.use(cookieParser());

//register a user
app.post("/api/register", async (request, response) => {
  let { body } = request;
  const { password: actual_password } = body;
  body = { ...body, password: hashPassword(actual_password) };
  let newUser;
  try {
    newUser = await new User(body).save();
  } catch (error) {
    response.status(400).send({ msg: "Unable to add user to the db" });
  }
  const { password, ...data } = body;
  response.status(200).send({ msg: "User added successfully", user: data });
});

// user login and generating a token when a user logs in
app.post("/api/login", async (request, response) => {
  const { email, password } = request.body;
  let findUser;
  try {
    findUser = await User.findOne({ email });
    if (!findUser) throw new Error("invalid email");
    if (!bcrypt.compareSync(password, findUser.password))
      throw new Error("invalid credentials");
  } catch (error) {
    response.status(400).send({ error: error.message });
  }
  const token = jwt.sign({ id: findUser._id }, process.env.JWT_SECRET);
  response.cookie("token", token, { httpOnly: true, maxAge: 1000 * 60 }); //max age one minute just for testing
  response.status(200).send({ msg: "Logged in successfully", token });
});

app.get("/api/users", isAuthenticated, async (request, response) => {
  const userObj = request.user.toObject();
  delete userObj.password;
  const allUsers = await User.find({}, { password: false });
  response.status(200).send({ allUsers, requestBy: userObj });
});

app.listen(4000, () => console.log(`Listening at port 4000`));
