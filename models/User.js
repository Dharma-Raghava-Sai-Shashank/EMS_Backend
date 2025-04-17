const mongoose = require("mongoose");
const { Schema } = mongoose;

const UserSchema = new Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: {
      type: String,
      enum: ["user", "organizer", "venue_owner"],
      required: true,
    },
    venues: [
      {
        type: Schema.Types.ObjectId,
        ref: "Venue",
      },
    ],
    venueDetails: {
      venueName: String,
      address: String,
      capacity: Number,
      pricePerDay: Number,
      amenities: [String],
      images: [String],
    },
    organizationDetails: {
      organizationName: String,
      contactNumber: String,
      previousEvents: [String],
    },
  },
  { timestamps: true }
);

const UserModel = mongoose.model("User", UserSchema);

module.exports = UserModel;
