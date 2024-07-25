const User = require("../models/User");
const { StatusCodes } = require("http-status-codes");
const {
  NotFoundError,
  BadRequestError,
  UnauthenticatedError,
} = require("../errors");
const {
  createTokenUser,
  attachCookiesToResponse,
  checkPermissions,
} = require("../utils");

const getAllUsers = async (req, res) => {
  const users = await User.find({ role: "user" }).select("-password");
  res.status(StatusCodes.OK).json({ users });
};

const getSingleUser = async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id).select("-password");
  if (!user) {
    throw new NotFoundError(`Could not find a user with id : ${id}`);
  }
  checkPermissions(req.user, user._id);
  res.status(StatusCodes.OK).json({ user });
};

const showCurrentUser = async (req, res) => {
  res.status(StatusCodes.OK).json({ user: req.user });
};

const updateUser = async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) {
    throw new BadRequestError("Provide email and name");
  }

  const user = await User.findById(req.user.userId);

  user.email = email;
  user.name = name;
  await user.save();

  const tokenUser = createTokenUser(user);
  attachCookiesToResponse({ res, user: tokenUser });
  res.status(StatusCodes.OK).json({ user: tokenUser });
};

const updateUserPassword = async (req, res) => {
  // Check for valid inputs
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    throw new BadRequestError(
      "Please provide the old password and new password"
    );
  }

  // check for valid password
  const user = await User.findById(req.user.userId);
  const isMatch = await user.comparePassword(oldPassword);
  if (!isMatch) {
    throw new UnauthenticatedError("Incorrect password");
  }

  // Update password
  user.password = newPassword;
  await user.save();
  res.status(StatusCodes.OK).json({ msg: "Password changed" });
};

module.exports = {
  getAllUsers,
  getSingleUser,
  showCurrentUser,
  updateUser,
  updateUserPassword,
};
