const { Schema, model } = require("mongoose");

const userSchema = Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    trim: true,
  },

  passwordHash: {
    type: String,
    required: true,
  },
  address: String,
  country: String,
  postalCode: String,
  phone: {
    type: String,
    required: true,
    trim: true,
  },
  isAdmin: {
    type: Boolean,
    default: false,
  },
  resetPasswordOTP: {
    type: Number,
  },
  resetPasswordOTPExpires: Date,
  bookingHistory: [
    {
      hotelId: { type: Schema.Types.ObjectId, ref: "Hotel", require: true },
      hotelName: {type: String, require: true},
      hotelFeatureImage: {type: String, require: true},
      hotelBookingPrice: {type: Number, require: true}
    },
  ],
});

userSchema.index({ email: 1 }, { unique: true });

exports.User = model("User", userSchema);
