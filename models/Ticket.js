const mongoose = require("mongoose");

const ticketSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    eventId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Event",
      required: true,
    },
    quantity: {
      type: Number,
      required: true,
    },
    totalAmount: {
      type: Number,
      required: true,
    },
    eventDetails: {
      title: { type: String, required: true },
      date: { type: Date, required: true },
      time: { type: String, required: true },
      venue: { type: String, required: true },
      location: { type: String, required: true },
      description: { type: String, required: true },
      price: { type: Number, required: true },
    },
    ticketDetails: {
      price: { type: Number, required: true },
      purchaseDate: { type: Date, default: Date.now },
    },
    qrCode: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ["active", "cancelled", "used"],
      default: "active",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Ticket", ticketSchema);
