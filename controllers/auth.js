const { validationResult } = require("express-validator");
const { User } = require("../models/user");
const bcrypt = require("bcrypt");
const  Jwt  = require("jsonwebtoken");
const { Token } = require("../models/token");
const mailSender = require('../helpers/email_sender')

exports.register = async function (req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map((error) => ({
      field: error.path,
      message: error.msg,
    }));
    return res.status(400).json({ errors: errorMessages });
  }
  try {
    let user = new User({
      ...req.body,
      passwordHash: bcrypt.hashSync(req.body.password, 8),
    });

    user = await user.save();
    if (!user) {
      return res.status(500).json({
        type: 'Internal Server Error',
        message: 'Could not create a new user',
      });
    }

    return res.status(201).json(user);
  } catch (error) {
    if (error.message.includes('email_1 dup key')) {
      return res.status(409).json({
        type: 'AuthError',
        message: 'User with that email already exists.',
      });
    }
    return res.status(500).json({ type: error.name, message: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const {email, password} = req.body
    const user = await User.findOne({email: email});
    if(!user) {
      return res.status(404).json({message: "User not found, check your email."})
    }
    if(!bcrypt.compare(password, user.passwordHash)) {
      res.status(400).json({message: "Incorrect password!!!!"})
    }

    const accessToken = Jwt.sign(
      {id: user.id, isAdmin: user.isAdmin},
      process.env.ACCESS_TOKEN_SECRET,
      {expiresIn: '24h'}
    );

    const refreshToken = Jwt.sign(
      {id: user.id, isAdmin: user.isAdmin},
      process.env.REFRESH_TOKEN_SECRET,
      {expiresIn: '60d'}
    );


    const token = Token.findOne({userId: user.id});
  
    if(token) await token.deleteOne()
    await new Token({userId: user.id, accessToken, refreshToken}).save();

    user.passwordHash = undefined

    return res.json({...user._doc, accessToken})

  } catch (error) {
    return res.status(500).json({ type: error.name, message: error.message });
  }
};

exports.verifyToken = async (req, res) => {
  try {
    let accessToken = req.headers.authorization;
    if (!accessToken) return res.json(false);
    accessToken = accessToken.replace('Bearer', '').trim();

    const token = await Token.findOne({ accessToken });
    if (!token) return res.json(false);

    const tokenData = jwt.decode(token.refreshToken);

    const user = await User.findById(tokenData.id).select('-password');
    if (!user) return res.json(false);

    const isValid = jwt.verify(
      token.refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    if (!isValid) return res.json(false);
    return res.json({success: true, user});
  } catch (error) {
    return res.status(500).json({ type: error.name, message: error.message });
  }
}

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ message: 'User with that email does NOT exist!' });
    }

    const otp = Math.floor(1000 + Math.random() * 9000);

    user.resetPasswordOTP = otp;
    user.resetPasswordOTPExpires = Date.now() + 600000;

    await user.save();

    const response = await mailSender.sendMail(
      email,
      'Password Reset OTP',
      `Your OTP for password reset is: ${otp}`
    );
    return res.json({ message: response });
  } catch (error) {
    return res.status(500).json({ type: error.name, message: error.message });
  }
};

exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }

    if (
      user.resetPasswordOTP !== +otp ||
      Date.now() > user.resetPasswordOTPExpires
    ) {
      return res.status(401).json({ message: 'Invalid or expired OTP' });
    }
    user.resetPasswordOTP = 1;
    user.resetPasswordOTPExpires = undefined;

    await user.save();
    return res.json({ message: 'OTP confirmed successfully.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ type: error.name, message: error.message });
  }
};

exports.resetPassword = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map((error) => ({
      field: error.path,
      message: error.msg,
    }));
    return res.status(400).json({ errors: errorMessages });
  }
  try {
    const { email, newPassword } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }

    if (user.resetPasswordOTP !== 1) {
      return res
        .status(401)
        .json({ message: 'Confirm OTP before resetting password.' });
    }

    user.passwordHash = bcrypt.hashSync(newPassword, 8);
    user.resetPasswordOTP = undefined;
    await user.save();

    return res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ type: error.name, message: error.message });
  }
};
