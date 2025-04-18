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

const app = express();

// Constants
const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET || "bsbsfbrnsftentwnnwnwn";

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: process.env.Frontend_URL,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Database Connection
mongoose.connect(process.env.MONGO_URL);

// Multer Configuration
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

// ======================
// Authentication Routes
// ======================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new UserModel({
      name,
      email,
      password: hashedPassword,
      role,
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      jwtSecret,
      { expiresIn: "7d" }
    );

    // Remove password from user object
    const userWithoutPassword = user.toObject();
    delete userWithoutPassword.password;

    res.status(201).json({ token, user: userWithoutPassword });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      jwtSecret,
      { expiresIn: "7d" }
    );

    // Remove password from user object
    const userWithoutPassword = user.toObject();
    delete userWithoutPassword.password;

    res.json({ token, user: userWithoutPassword });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed", details: error.message });
  }
});

app.get("/profile", auth, async (req, res) => {
  try {
    const user = await UserModel.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      name: user.name,
      email: user.email,
      _id: user._id,
      role: user.role,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

app.post("/logout", (req, res) => {
  res.json({ message: "Logged out successfully" });
});

// ======================
// Venue Management Routes
// ======================
app.post("/venues", auth, upload.array("images", 5), async (req, res) => {
  try {
    if (!req.user || req.user.role !== "venue_owner") {
      return res
        .status(403)
        .json({ error: "Only venue owners can create venues" });
    }

    const venueData = { ...req.body };
    venueData.capacity = Number(venueData.capacity);
    venueData.pricePerDay = Number(venueData.pricePerDay);
    venueData.availability =
      venueData.availability === "true" || venueData.availability === true;

    if (typeof venueData.amenities === "string") {
      try {
        venueData.amenities = JSON.parse(venueData.amenities);
      } catch (e) {
        console.error("Error parsing amenities:", e);
        return res.status(400).json({ error: "Invalid amenities format" });
      }
    }

    if (req.files && req.files.length > 0) {
      venueData.images = req.files.map((file) => file.path);
    }

    venueData.owner = req.user._id;

    const requiredFields = ["name", "address", "capacity", "pricePerDay"];
    const missingFields = requiredFields.filter((field) => !venueData[field]);
    if (missingFields.length > 0) {
      return res.status(400).json({
        error: "Missing required fields",
        details: `Missing: ${missingFields.join(", ")}`,
      });
    }

    const venue = await VenueModel.create(venueData);
    await UserModel.findByIdAndUpdate(req.user._id, {
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

// ======================
// Event Management Routes
// ======================
app.post(
  "/events",
  auth,
  checkRole(["organizer"]),
  upload.array("images", 5),
  async (req, res) => {
    try {
      const eventData = { ...req.body };
      eventData.images = req.files ? req.files.map((file) => file.path) : [];
      eventData.organizer = req.user._id;

      eventData.expectedAttendees = Number(eventData.expectedAttendees);
      eventData.budget = Number(eventData.budget);
      eventData.price = Number(eventData.price);

      if (eventData.date) {
        eventData.eventDate = eventData.date;
        delete eventData.date;
      }
      if (eventData.time) {
        eventData.eventTime = eventData.time;
        delete eventData.time;
      }

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
        return res.status(400).json({
          error: "Missing required fields",
          details: `Please fill in the following fields: ${missingFields.join(
            ", "
          )}`,
        });
      }

      const venue = await VenueModel.findById(eventData.venue);
      if (!venue) {
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

      const eventDuration = 1;
      const venueCost = venue.pricePerDay * eventDuration;
      if (eventData.budget < venueCost) {
        return res.status(400).json({
          error: "Insufficient budget",
          details: `Budget (${eventData.budget}) is insufficient for venue cost (${venueCost})`,
        });
      }

      const event = await EventModel.create(eventData);
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

app.get("/events", auth, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === "organizer") {
      query.organizer = req.user._id;
    } else if (req.user.role === "venue_owner") {
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
    res.status(500).json({
      error: "Failed to fetch events",
      details: error.message,
    });
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

// ======================
// Venue Owner Routes
// ======================
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

// ======================
// Review Routes
// ======================
app.post("/venues/:id/reviews", auth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const venue = await VenueModel.findById(req.params.id);

    venue.reviews.push({
      user: req.user._id,
      rating,
      comment,
    });

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

// ======================
// Ticket Management Routes
// ======================
app.post("/tickets", auth, async (req, res) => {
  try {
    const ticketData = req.body;

    if (
      !ticketData.userId ||
      !ticketData.eventId ||
      !ticketData.quantity ||
      !ticketData.totalAmount ||
      !ticketData.eventDetails ||
      !ticketData.ticketDetails ||
      !ticketData.qrCode
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (
      !ticketData.eventDetails.title ||
      !ticketData.eventDetails.date ||
      !ticketData.eventDetails.time ||
      !ticketData.eventDetails.venue ||
      !ticketData.eventDetails.price
    ) {
      return res.status(400).json({ error: "Missing required event details" });
    }

    if (
      !ticketData.ticketDetails.price ||
      !ticketData.ticketDetails.purchaseDate
    ) {
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

// ======================
// Venue Request Routes
// ======================
app.get("/event/venue-requests", auth, async (req, res) => {
  try {
    const user = await UserModel.findById(req.user._id);

    if (!user || user.role !== "venue_owner") {
      return res.status(403).json({ error: "Unauthorized" });
    }

    if (!user.venues || user.venues.length === 0) {
      return res.status(404).json({ error: "No venues found for this user" });
    }

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

    if (!events || events.length === 0) {
      return res.status(200).json([]);
    }

    res.json(events);
  } catch (err) {
    console.error("Error in venue requests endpoint:", err);
    res.status(500).json({
      error: "Failed to fetch venue requests",
      details: err.message,
    });
  }
});

app.patch("/vevent/:id/venue-request", auth, async (req, res) => {
  try {
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

// ======================
// User Events Routes
// ======================
app.get("/my-events", auth, async (req, res) => {
  try {
    const user = await UserModel.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let events;
    if (user.role === "organizer") {
      events = await EventModel.find({ organizer: user._id })
        .populate("venue", "name address")
        .populate("organizer", "name email")
        .sort({ createdAt: -1 });
    } else if (user.role === "venue_owner") {
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

    res.json(events);
  } catch (error) {
    console.error("Error fetching user's events:", error);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

app.get("/my-venues", auth, checkRole(["venue_owner"]), async (req, res) => {
  try {
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

    res.json(venues);
  } catch (error) {
    console.error("Error fetching venues:", error);
    res.status(500).json({ error: "Failed to fetch venues" });
  }
});

// Start Server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
