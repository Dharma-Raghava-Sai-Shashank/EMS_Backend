const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema(
  {
    organizer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    venue: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Venue",
      required: true,
    },
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    eventDate: {
      type: Date,
      required: true,
    },
    eventTime: {
      type: String,
      required: true,
    },
    expectedAttendees: {
      type: Number,
      required: true,
      min: 1,
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected", "completed", "cancelled"],
      default: "pending",
    },
    price: {
      type: Number,
      required: true,
      min: 0,
    },
    requirements: [String],
    images: [String],
    category: {
      type: String,
      required: true,
      enum: ["Conference", "Workshop", "Seminar", "Party", "Wedding", "Other"],
    },
    attendees: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    reviews: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        rating: Number,
        comment: String,
        date: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    venueRequest: {
      status: {
        type: String,
        enum: ["pending", "approved", "rejected"],
        default: "pending",
      },
      message: String,
      response: String,
      requestedAt: {
        type: Date,
        default: Date.now,
      },
      respondedAt: Date,
    },
    budget: {
      type: Number,
      required: true,
    },
  },
  { timestamps: true }
);

// Pre-save middleware to validate event details against venue
eventSchema.pre("save", async function (next) {
  try {
    const venue = await mongoose.model("Venue").findById(this.venue);

    if (!venue) {
      throw new Error("Venue not found");
    }

    // Check if venue is available
    if (!venue.availability) {
      throw new Error("Venue is not available");
    }

    // Check if expected attendees exceed venue capacity
    if (this.expectedAttendees > venue.capacity) {
      throw new Error(
        `Expected attendees (${this.expectedAttendees}) exceed venue capacity (${venue.capacity})`
      );
    }

    // Check if budget is sufficient for venue price
    const eventDuration = 1; // Assuming 1 day for now
    const venueCost = venue.pricePerDay * eventDuration;
    if (this.budget < venueCost) {
      throw new Error(
        `Budget (${this.budget}) is insufficient for venue cost (${venueCost})`
      );
    }

    next();
  } catch (error) {
    next(error);
  }
});

module.exports = mongoose.model("Event", eventSchema);
