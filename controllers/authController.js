const User = require("../models/User");
const {
  BadRequestError,
  CustomAPIError,
  UnauthenticatedError,
} = require("../errors");
const { StatusCodes } = require("http-status-codes");
const { attachCookiesToResponse, createTokenUser } = require("../utils");

const register = async (req, res) => {
  const { name, email, password } = req.body;

  // check inputs are provided
  if (!name || !email || !password) {
    throw new BadRequestError("Please provide name, email and password");
  }

  // check email is unique
  const emailExists = await User.findOne({ email });
  if (emailExists) {
    throw new CustomAPIError("Email is already taken", StatusCodes.CONFLICT);
  }

  // First user account is admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? "admin" : "user";

  // create user and respond
  const user = await User.create({ name, email, password, role });
  const tokenUser = createTokenUser(user);

  attachCookiesToResponse({ res, user: tokenUser });
  res.status(StatusCodes.CREATED).json({ user: tokenUser });
};

const login = async (req, res) => {
  const { email, password } = req.body;

  // check inputs are provided
  if (!email || !password) {
    throw new BadRequestError("Please provide email and password");
  }

  // Find user
  const user = await User.findOne({ email });
  if (!user) {
    throw new UnauthenticatedError(`No user found with email : ${email}`);
  }

  // check password
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Incorrect password");
  }

  // send response
  const tokenUser = createTokenUser(user);
  attachCookiesToResponse({ res, user: tokenUser });
  res.status(StatusCodes.OK).json({ user: tokenUser });
};

const logout = async (req, res) => {
  res.cookie("token", "logout", {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.status(StatusCodes.OK).json({ msg: "user logged out" });
};

module.exports = { register, logout, login };
