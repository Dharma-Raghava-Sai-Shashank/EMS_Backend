const express = require("express");
const cors = require("cors");
require("dotenv").config();
const mongoose = require("mongoose");
const UserModel = require("./models/User");
const VenueModel = require("./models/Venue");
const EventModel = require("./models/Event");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const { auth, checkRole } = require("./middleware/auth");
const Ticket = require("./models/Ticket");
const User = require("./models/User");
const Event = require("./models/Event");

const app = express();

const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET || "bsbsfbrnsftentwnnwnwn";

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: process.env.Frontend_URL,
  })
);

mongoose.connect(process.env.MONGO_URL);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
      return cb(new Error("Only image files are allowed!"), false);
    }
    cb(null, true);
  },
});

app.get("/test", (req, res) => {
  res.json("test ok");
});

app.post("/register", async (req, res) => {
  const { name, email, password, role, venueDetails, organizationDetails } =
    req.body;

  try {
    const userDoc = await UserModel.create({
      name,
      email,
      password: bcrypt.hashSync(password, bcryptSalt),
      role,
      ...(role === "venue_owner" ? { venueDetails } : {}),
      ...(role === "organizer" ? { organizationDetails } : {}),
    });
    res.json(userDoc);
  } catch (e) {
    res.status(422).json(e);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const userDoc = await UserModel.findOne({ email });

  if (!userDoc) {
    return res.status(404).json({ error: "User not found" });
  }

  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (!passOk) {
    return res.status(401).json({ error: "Invalid password" });
  }

  jwt.sign(
    {
      email: userDoc.email,
      id: userDoc._id,
    },
    jwtSecret,
    {},
    (err, token) => {
      if (err) {
        return res.status(500).json({ error: "Failed to generate token" });
      }
      res.cookie("token", token).json(userDoc);
    }
  );
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      const { name, email, _id, role } = await UserModel.findById(userData.id);
      res.json({ name, email, _id, role });
    });
  } else {
    res.json(null);
  }
});

app.post("/logout", (req, res) => {
  res.cookie("token", "").json(true);
});

// Venue Management endpoints
app.post("/venues", auth, upload.array("images", 5), async (req, res) => {
  try {
    if (!req.user || req.user.role !== "venue_owner") {
      return res
        .status(403)
        .json({ error: "Only venue owners can create venues" });
    }

    const venueData = { ...req.body };

    // Convert string values to numbers
    venueData.capacity = Number(venueData.capacity);
    venueData.pricePerDay = Number(venueData.pricePerDay);
    venueData.availability =
      venueData.availability === "true" || venueData.availability === true;

    // Parse amenities if it's a string
    if (typeof venueData.amenities === "string") {
      try {
        venueData.amenities = JSON.parse(venueData.amenities);
      } catch (e) {
        console.error("Error parsing amenities:", e);
        return res.status(400).json({ error: "Invalid amenities format" });
      }
    }

    // Handle images from multer
    if (req.files && req.files.length > 0) {
      venueData.images = req.files.map((file) => file.path);
    }

    // Set the owner
    venueData.owner = req.user._id;

    // Validate required fields
    const requiredFields = ["name", "address", "capacity", "pricePerDay"];
    const missingFields = requiredFields.filter((field) => !venueData[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({
        error: "Missing required fields",
        details: `Missing: ${missingFields.join(", ")}`,
      });
    }

    console.log("Creating venue with data:", venueData);

    // Create the venue
    const venue = await VenueModel.create(venueData);

    // Add the venue to the user's venues array
    await User.findByIdAndUpdate(req.user._id, {
      $push: { venues: venue._id },
    });

    res.status(201).json(venue);
  } catch (err) {
    console.error("Error creating venue:", err);
    res.status(500).json({
      error: "Failed to create venue",
      details: err.message,
    });
  }
});

app.get("/venues", async (req, res) => {
  try {
    let query = {};

    // If user is logged in and is a venue owner, show only their venues
    if (req.user && req.user.role === "venue_owner") {
      query.owner = req.user._id;
    }

    const venues = await VenueModel.find(query).populate("owner", "name email");
    res.json(venues);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch venues" });
  }
});

app.get("/venues/:id", async (req, res) => {
  try {
    const venue = await VenueModel.findById(req.params.id)
      .populate("owner", "name email")
      .populate("reviews.user", "name");
    res.json(venue);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch venue" });
  }
});

// Event Management endpoints
app.post(
  "/events",
  auth,
  checkRole(["organizer"]),
  upload.array("images", 5),
  async (req, res) => {
    try {
      console.log("Received event data:", req.body);
      console.log("Received files:", req.files);
      console.log("User:", req.user);

      const eventData = { ...req.body };

      // Handle images
      eventData.images = req.files ? req.files.map((file) => file.path) : [];
      eventData.organizer = req.user._id;

      // Convert string values to numbers
      eventData.expectedAttendees = Number(eventData.expectedAttendees);
      eventData.budget = Number(eventData.budget);
      eventData.price = Number(eventData.price);

      // Map date and time to eventDate and eventTime
      if (eventData.date) {
        eventData.eventDate = eventData.date;
        delete eventData.date;
      }
      if (eventData.time) {
        eventData.eventTime = eventData.time;
        delete eventData.time;
      }

      // Validate required fields
      const requiredFields = [
        "title",
        "description",
        "venue",
        "eventDate",
        "eventTime",
        "expectedAttendees",
        "budget",
        "category",
        "price",
      ];

      const missingFields = requiredFields.filter((field) => !eventData[field]);

      if (missingFields.length > 0) {
        console.error("Missing required fields:", missingFields);
        return res.status(400).json({
          error: "Missing required fields",
          details: `Please fill in the following fields: ${missingFields.join(
            ", "
          )}`,
        });
      }

      // Check venue availability and capacity
      const venue = await VenueModel.findById(eventData.venue);
      if (!venue) {
        console.error("Venue not found:", eventData.venue);
        return res.status(404).json({ error: "Venue not found" });
      }

      if (!venue.availability) {
        return res.status(400).json({
          error: "Venue not available",
          details: "This venue is currently unavailable",
        });
      }

      if (eventData.expectedAttendees > venue.capacity) {
        return res.status(400).json({
          error: "Capacity exceeded",
          details: `Expected attendees (${eventData.expectedAttendees}) exceed venue capacity (${venue.capacity})`,
        });
      }

      // Check budget
      const eventDuration = 1; // Assuming 1 day for now
      const venueCost = venue.pricePerDay * eventDuration;
      if (eventData.budget < venueCost) {
        return res.status(400).json({
          error: "Insufficient budget",
          details: `Budget (${eventData.budget}) is insufficient for venue cost (${venueCost})`,
        });
      }

      console.log("Creating event with data:", eventData);
      const event = await EventModel.create(eventData);
      console.log("Event created successfully:", event);
      res.status(201).json(event);
    } catch (error) {
      console.error("Event creation error:", error);
      res.status(500).json({
        error: "Failed to create event",
        details: error.message,
      });
    }
  }
);

app.get("/events", async (req, res) => {
  try {
    let query = {};

    // If user is logged in and is an organizer, show only their events
    if (req.user && req.user.role === "organizer") {
      query.organizer = req.user._id;
    }
    // If user is logged in and is a venue owner, show only events for their venues
    else if (req.user && req.user.role === "venue_owner") {
      const user = await UserModel.findById(req.user._id);
      if (!user.venues || user.venues.length === 0) {
        return res.status(200).json([]);
      }
      query.venue = { $in: user.venues };
    }

    const events = await EventModel.find(query)
      .populate("organizer", "name email")
      .populate("venue", "name address");
    res.json(events);
  } catch (error) {
    console.error("Error fetching events:", error);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

app.get("/events/:id", async (req, res) => {
  try {
    const event = await EventModel.findById(req.params.id)
      .populate("organizer", "name email")
      .populate("venue", "name address capacity amenities")
      .populate("attendees", "name email");
    res.json(event);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch event" });
  }
});

// Venue owner endpoints
app.put(
  "/venues/:id/availability",
  auth,
  checkRole(["venue_owner"]),
  async (req, res) => {
    try {
      const { availability } = req.body;
      const venue = await VenueModel.findById(req.params.id);

      if (!venue) {
        return res.status(404).json({ error: "Venue not found" });
      }

      if (venue.owner.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: "Not authorized" });
      }

      venue.availability = availability;
      await venue.save();

      res.json(venue);
    } catch (error) {
      console.error("Error updating venue availability:", error);
      res.status(500).json({
        error: "Failed to update availability",
        details: error.message,
      });
    }
  }
);

// Event approval endpoint for venue owners
app.put(
  "/events/:id/status",
  auth,
  checkRole(["venue_owner"]),
  async (req, res) => {
    try {
      const { status } = req.body;
      const event = await EventModel.findById(req.params.id);
      const venue = await VenueModel.findById(event.venue);

      if (venue.owner.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: "Not authorized" });
      }

      event.status = status;
      await event.save();
      res.json(event);
    } catch (error) {
      res.status(500).json({ error: "Failed to update event status" });
    }
  }
);

// Review endpoints
app.post("/venues/:id/reviews", auth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const venue = await VenueModel.findById(req.params.id);

    venue.reviews.push({
      user: req.user._id,
      rating,
      comment,
    });

    // Update average rating
    const totalRating = venue.reviews.reduce(
      (sum, review) => sum + review.rating,
      0
    );
    venue.rating = totalRating / venue.reviews.length;

    await venue.save();
    res.json(venue);
  } catch (error) {
    res.status(500).json({ error: "Failed to add review" });
  }
});

app.post("/events/:id/reviews", auth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const event = await EventModel.findById(req.params.id);

    event.reviews.push({
      user: req.user._id,
      rating,
      comment,
    });

    await event.save();
    res.json(event);
  } catch (error) {
    res.status(500).json({ error: "Failed to add review" });
  }
});

app.post("/tickets", auth, async (req, res) => {
  try {
    const ticketData = req.body;

    // Validate required fields
    if (
      !ticketData.userId ||
      !ticketData.eventId ||
      !ticketData.quantity ||
      !ticketData.totalAmount ||
      !ticketData.eventDetails ||
      !ticketData.ticketDetails ||
      !ticketData.qrCode
    ) {
      console.log("Missing fields:", {
        userId: ticketData.userId,
        eventId: ticketData.eventId,
        quantity: ticketData.quantity,
        totalAmount: ticketData.totalAmount,
        eventDetails: ticketData.eventDetails,
        ticketDetails: ticketData.ticketDetails,
        qrCode: ticketData.qrCode,
      });
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Validate eventDetails fields
    if (
      !ticketData.eventDetails.title ||
      !ticketData.eventDetails.date ||
      !ticketData.eventDetails.time ||
      !ticketData.eventDetails.venue ||
      !ticketData.eventDetails.price
    ) {
      console.log("Missing eventDetails fields:", ticketData.eventDetails);
      return res.status(400).json({ error: "Missing required event details" });
    }

    // Validate ticketDetails fields
    if (
      !ticketData.ticketDetails.price ||
      !ticketData.ticketDetails.purchaseDate
    ) {
      console.log("Missing ticketDetails fields:", ticketData.ticketDetails);
      return res.status(400).json({ error: "Missing required ticket details" });
    }

    const newTicket = new Ticket(ticketData);
    await newTicket.save();

    return res.status(201).json({
      success: true,
      ticket: newTicket,
    });
  } catch (error) {
    console.error("Error creating ticket:", error);
    return res.status(500).json({
      error: "Failed to create ticket",
      details: error.message,
    });
  }
});

app.get("/tickets/:id", async (req, res) => {
  try {
    const tickets = await Ticket.find();
    res.json(tickets);
  } catch (error) {
    console.error("Error fetching tickets:", error);
    res.status(500).json({ error: "Failed to fetch tickets" });
  }
});

app.get("/tickets/user/:userId", (req, res) => {
  const userId = req.params.userId;

  Ticket.find({ userId: userId })
    .populate("eventId")
    .then((tickets) => {
      res.json(tickets);
    })
    .catch((error) => {
      console.error("Error fetching user tickets:", error);
      res.status(500).json({ error: "Failed to fetch user tickets" });
    });
});

app.delete("/tickets/:id", async (req, res) => {
  try {
    const ticketId = req.params.id;
    await Ticket.findByIdAndDelete(ticketId);
    res.status(204).send();
  } catch (error) {
    console.error("Error deleting ticket:", error);
    res.status(500).json({ error: "Failed to delete ticket" });
  }
});

// Get venue requests for venue owners
app.get("/event/venue-requests", auth, async (req, res) => {
  try {
    console.log("Fetching venue requests...");

    const user = await UserModel.findById(req.user._id);
    console.log("User found:", user ? user._id : "No user found");

    if (!user || user.role !== "venue_owner") {
      console.log("Unauthorized access attempt");
      return res.status(403).json({ error: "Unauthorized" });
    }

    if (!user.venues || user.venues.length === 0) {
      console.log("No venues found for user:", user._id);
      return res.status(404).json({ error: "No venues found for this user" });
    }

    console.log("User's venues:", user.venues);

    // Find all events that have a venue request and the venue belongs to the current user
    const events = await EventModel.find({
      "venueRequest.status": "pending",
      venue: { $in: user.venues },
    })
      .populate({
        path: "organizer",
        select: "name email",
      })
      .populate({
        path: "venue",
        select: "name address capacity pricePerDay availability",
      })
      .sort({ "venueRequest.requestedAt": -1 });

    console.log("Found events:", events ? events.length : 0);
    console.log("Events details:", events);

    if (!events || events.length === 0) {
      console.log("No events found with pending venue requests");
      return res.status(200).json([]);
    }

    res.json(events);
  } catch (err) {
    console.error("Error in venue requests endpoint:", err);
    console.error("Error stack:", err.stack);
    res.status(500).json({
      error: "Failed to fetch venue requests",
      details: err.message,
    });
  }
});

// Handle venue request action
app.patch("/vevent/:id/venue-request", auth, async (req, res) => {
  try {
    console.log("Received request body:", req.body);
    const { action, response } = req.body;
    const event = await EventModel.findById(req.params.id);

    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }

    if (
      req.user.role !== "venue_owner" ||
      !req.user.venues.includes(event.venue)
    ) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    event.venueRequest.status = action;
    event.venueRequest.response = response;
    event.venueRequest.respondedAt = new Date();
    event.status = action === "approved" ? "approved" : "rejected";

    await event.save();

    res.json({ success: true, event });
  } catch (error) {
    console.error("Error processing venue request:", error);
    res.status(500).json({ error: "Failed to process venue request" });
  }
});

// Get user's events based on role
app.get("/my-events", auth, async (req, res) => {
  try {
    console.log("Fetching user's events...");
    const user = await UserModel.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let events;
    if (user.role === "organizer") {
      // For organizers, show events they created
      events = await EventModel.find({ organizer: user._id })
        .populate("venue", "name address")
        .populate("organizer", "name email")
        .sort({ createdAt: -1 });
    } else if (user.role === "venue_owner") {
      // For venue owners, show events at their venues
      if (!user.venues || user.venues.length === 0) {
        return res.status(200).json([]);
      }
      events = await EventModel.find({ venue: { $in: user.venues } })
        .populate("venue", "name address")
        .populate("organizer", "name email")
        .sort({ createdAt: -1 });
    } else {
      return res.status(403).json({ error: "Unauthorized role" });
    }

    console.log(`Found ${events.length} events for user ${user._id}`);
    res.json(events);
  } catch (error) {
    console.error("Error fetching user's events:", error);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// Get venue owner's venues
app.get("/my-venues", auth, checkRole(["venue_owner"]), async (req, res) => {
  try {
    console.log("Fetching user's venues...");
    const user = await UserModel.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.venues || user.venues.length === 0) {
      return res.status(200).json([]);
    }

    const venues = await VenueModel.find({ _id: { $in: user.venues } })
      .populate("owner", "name email")
      .sort({ createdAt: -1 });

    console.log(`Found ${venues.length} venues for user ${user._id}`);
    res.json(venues);
  } catch (error) {
    console.error("Error fetching venues:", error);
    res.status(500).json({ error: "Failed to fetch venues" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
