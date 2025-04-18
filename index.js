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

// ======================
// Authentication Routes
// ======================
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
  if (userDoc) {
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (passOk) {
      jwt.sign(
        { email: userDoc.email, id: userDoc._id },
        jwtSecret,
        {},
        (err, token) => {
          if (err) throw err;
          res.cookie("token", token).json(userDoc);
        }
      );
    } else {
      res.status(422).json("pass not ok");
    }
  } else {
    res.json("not found");
  }
});

app.post("/logout", (req, res) => {
  res.cookie("token", "").json(true);
});

// ======================
// User Profile Routes
// ======================
app.get("/profile", auth, async (req, res) => {
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

app.put("/profile", auth, upload.single("avatar"), async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = await UserModel.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.name = name || user.name;
    user.email = email || user.email;

    if (req.file) {
      user.avatar = req.file.path;
    }

    await user.save();
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// ======================
// Venue Management Routes
// ======================
app.post(
  "/venues",
  auth,
  checkRole(["venue_owner"]),
  upload.array("images", 5),
  async (req, res) => {
    try {
      const venueData = { ...req.body };
      venueData.owner = req.user._id;
      venueData.images = req.files.map((file) => file.path);
      venueData.capacity = Number(venueData.capacity);
      venueData.pricePerDay = Number(venueData.pricePerDay);
      venueData.availability = venueData.availability === "true";

      const venue = await VenueModel.create(venueData);
      await UserModel.findByIdAndUpdate(req.user._id, {
        $push: { venues: venue._id },
      });
      res.json(venue);
    } catch (error) {
      res.status(500).json({ error: "Failed to create venue" });
    }
  }
);

app.get("/venues", async (req, res) => {
  try {
    const venues = await VenueModel.find()
      .populate("owner", "name email")
      .populate("reviews.user", "name");
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

app.put(
  "/venues/:id",
  auth,
  checkRole(["venue_owner"]),
  upload.array("images", 5),
  async (req, res) => {
    try {
      const venue = await VenueModel.findById(req.params.id);
      if (!venue) {
        return res.status(404).json({ error: "Venue not found" });
      }

      if (venue.owner.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: "Not authorized" });
      }

      const updateData = { ...req.body };
      if (req.files && req.files.length > 0) {
        updateData.images = req.files.map((file) => file.path);
      }

      const updatedVenue = await VenueModel.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true }
      );
      res.json(updatedVenue);
    } catch (error) {
      res.status(500).json({ error: "Failed to update venue" });
    }
  }
);

app.delete(
  "/venues/:id",
  auth,
  checkRole(["venue_owner"]),
  async (req, res) => {
    try {
      const venue = await VenueModel.findById(req.params.id);
      if (!venue) {
        return res.status(404).json({ error: "Venue not found" });
      }

      if (venue.owner.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: "Not authorized" });
      }

      await VenueModel.findByIdAndDelete(req.params.id);
      await UserModel.findByIdAndUpdate(req.user._id, {
        $pull: { venues: req.params.id },
      });
      res.json({ message: "Venue deleted successfully" });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete venue" });
    }
  }
);

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
      res.status(500).json({ error: "Failed to update availability" });
    }
  }
);

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
      eventData.organizer = req.user._id;
      eventData.images = req.files.map((file) => file.path);
      eventData.expectedAttendees = Number(eventData.expectedAttendees);
      eventData.budget = Number(eventData.budget);
      eventData.price = Number(eventData.price);

      const event = await EventModel.create(eventData);
      res.json(event);
    } catch (error) {
      res.status(500).json({ error: "Failed to create event" });
    }
  }
);

app.get("/events", async (req, res) => {
  try {
    const events = await EventModel.find()
      .populate("organizer", "name email")
      .populate("venue", "name address")
      .populate("attendees", "name email");
    res.json(events);
  } catch (error) {
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

app.put(
  "/events/:id",
  auth,
  checkRole(["organizer"]),
  upload.array("images", 5),
  async (req, res) => {
    try {
      const event = await EventModel.findById(req.params.id);
      if (!event) {
        return res.status(404).json({ error: "Event not found" });
      }

      if (event.organizer.toString() !== req.user._id.toString()) {
        return res.status(403).json({ error: "Not authorized" });
      }

      const updateData = { ...req.body };
      if (req.files && req.files.length > 0) {
        updateData.images = req.files.map((file) => file.path);
      }

      const updatedEvent = await EventModel.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true }
      );
      res.json(updatedEvent);
    } catch (error) {
      res.status(500).json({ error: "Failed to update event" });
    }
  }
);

app.delete("/events/:id", auth, checkRole(["organizer"]), async (req, res) => {
  try {
    const event = await EventModel.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }

    if (event.organizer.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: "Not authorized" });
    }

    await EventModel.findByIdAndDelete(req.params.id);
    res.json({ message: "Event deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete event" });
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

    const events = await EventModel.find({
      "venueRequest.status": "pending",
      venue: { $in: user.venues },
    })
      .populate("organizer", "name email")
      .populate("venue", "name address capacity pricePerDay availability")
      .sort({ "venueRequest.requestedAt": -1 });

    res.json(events);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch venue requests" });
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
    res.status(500).json({ error: "Failed to process venue request" });
  }
});

// ======================
// Ticket Management Routes
// ======================
app.post("/tickets", auth, async (req, res) => {
  try {
    const ticketData = req.body;
    const newTicket = new Ticket(ticketData);
    await newTicket.save();
    res.status(201).json(newTicket);
  } catch (error) {
    res.status(500).json({ error: "Failed to create ticket" });
  }
});

app.get("/tickets/user/:userId", auth, async (req, res) => {
  try {
    const tickets = await Ticket.find({ userId: req.params.userId })
      .populate("eventId")
      .sort({ purchaseDate: -1 });
    res.json(tickets);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch tickets" });
  }
});

// ======================
// Review Routes
// ======================
app.post("/events/:id/reviews", auth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const event = await EventModel.findById(req.params.id);

    if (!event) {
      return res.status(404).json({ error: "Event not found" });
    }

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
// User Events Routes
// ======================

app.get(
  "/my-venues",
  auth,
  checkRole(["venue_owner"]),
  async (req, res) => {
    try {
      const user = await UserModel.findById(req.user._id).populate("venues");
      res.json(user.venues);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch venues" });
    }
  }
);

app.get("/my-events", auth, async (req, res) => {
  try {
    const user = await UserModel.findById(req.user._id);
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
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
