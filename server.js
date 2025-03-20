require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { promises: dnsPromises } = require("dns");
const { Client, Account, Databases, Storage, ID, Query } = require("node-appwrite");
const Razorpay = require("razorpay");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const swaggerDocument = YAML.load("./swagger.yaml");
const cron = require("node-cron");
const admin = require("firebase-admin");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const path = require("path");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const morgan = require("morgan");
const winston = require("winston");

// Initialize Express and Middleware
const app = express();

// Configure Winston for logging
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

// Security Middleware
app.use(helmet()); // Set security headers
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://maps.googleapis.com", "https://api.razorpay.com"],
    },
  })
);
app.use(morgan("combined", { stream: { write: (message) => logger.info(message.trim()) } }));

// CORS Configuration
const corsOptions = {
  origin: "https://p2p-swapper-spark.lovable.app",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again after 15 minutes",
});
app.use(limiter);

// Serve static files for uploads
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Initialize Appwrite Client
const client = new Client()
  .setEndpoint(process.env.APPWRITE_ENDPOINT)
  .setProject(process.env.APPWRITE_PROJECT_ID)
  .setKey(process.env.APPWRITE_API_KEY);

const account = new Account(client);
const databases = new Databases(client);
const storageAppwrite = new Storage(client);

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Initialize Firebase for Push Notifications
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Configure Multer for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Ensure this directory exists
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("File must be an image"), false);
    }
  },
});

// Serve Swagger UI
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Utility Functions
const sendPushNotification = async (userId, title, body) => {
  try {
    const user = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      userId
    );
    if (user && user.fcm_token) {
      await admin.messaging().send({
        token: user.fcm_token,
        notification: { title, body },
      });
      logger.info(`Push notification sent to user ${userId}`);
    }
  } catch (error) {
    logger.error(`Error sending push notification to user ${userId}: ${error.message}`);
  }
};

const isDisposableEmail = async (email) => {
  try {
    const { default: fetch } = await import("node-fetch");
    const response = await fetch(`https://disify.com/api/email/${email}`);
    const data = await response.json();
    return data.disposable;
  } catch (error) {
    logger.error(`Error checking disposable email: ${error.message}`);
    return false;
  }
};

const checkMxRecord = async (domain) => {
  try {
    const addresses = await dnsPromises.resolveMx(domain);
    return addresses && addresses.length > 0;
  } catch (error) {
    logger.error(`Error checking MX record for domain ${domain}: ${error.message}`);
    return false;
  }
};

const isValidFutureDate = (dateStr) => {
  const inputDate = new Date(dateStr);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const sixMonthsLater = new Date();
  sixMonthsLater.setMonth(today.getMonth() + 6);
  return inputDate >= today && inputDate <= sixMonthsLater;
};

const sendNotification = async (userId, message) => {
  try {
    await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_NOTIFICATIONS_COLLECTION_ID,
      ID.unique(),
      { user_id: userId, message, created_at: new Date().toISOString() },
      [
        `read("user:${userId}")`,
        `write("user:${userId}")`,
        `update("user:${userId}")`,
        `delete("user:${userId}")`,
        `read("users")`,
      ]
    );
    await sendPushNotification(userId, "New Notification", message);
    logger.info(`Notification sent to user ${userId}: ${message}`);
  } catch (error) {
    logger.error(`Error sending notification to user ${userId}: ${error.message}`);
    throw error;
  }
};

// Token Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) {
    logger.warn("No token provided in request");
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.warn(`Invalid token: ${error.message}`);
    res.status(401).json({ error: "Invalid token" });
  }
};

// Admin Role Check Middleware
const verifyAdmin = async (req, res, next) => {
  try {
    const user = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      req.user.id
    );
    if (!user.is_admin) {
      logger.warn(`Unauthorized admin access attempt by user ${req.user.id}`);
      return res.status(403).json({ error: "Admin access required" });
    }
    next();
  } catch (error) {
    logger.error(`Error verifying admin role for user ${req.user.id}: ${error.message}`);
    res.status(500).json({ error: "Failed to verify admin role" });
  }
};

// Generate JWT Token
const generateToken = (userId, email) => {
  return jwt.sign({ id: userId, email }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Cron Jobs
// Traveler Profile Completion Reminder (Daily at Midnight)
cron.schedule("0 0 * * *", async () => {
  try {
    const users = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      [Query.equal("phone_number", null)]
    );
    for (const user of users.documents) {
      await sendNotification(user.$id, "Please complete your profile by adding a phone number!");
    }
    logger.info("Profile completion reminders sent successfully");
  } catch (error) {
    logger.error(`Error in profile completion cron job: ${error.message}`);
  }
});

// Automated Payout Scheduling (Every Hour)
cron.schedule("0 * * * *", async () => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const requests = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      [
        Query.equal("status", "delivered"),
        Query.greaterThanEqual("updated_at", oneHourAgo),
      ]
    );
    for (const request of requests.documents) {
      await razorpay.transfers.create({
        account: request.traveler_id,
        amount: request.reward * 100, // Use reward instead of price
        currency: "INR",
        notes: { purpose: "Automated Escrow Release" },
      });
      await databases.updateDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
        request.$id,
        { status: "paid" },
        [
          `read("user:${request.requester_id}")`,
          `write("user:${request.requester_id}")`,
          `update("user:${request.requester_id}")`,
          `delete("user:${request.requester_id}")`,
          `read("user:${request.traveler_id}")`,
          `write("user:${request.traveler_id}")`,
          `update("user:${request.traveler_id}")`,
          `delete("user:${request.traveler_id}")`,
          `read("users")`,
        ]
      );
      await sendNotification(
        request.traveler_id,
        `Payment of INR ${request.reward} has been released for request ${request.$id}`
      );
      logger.info(`Payout processed for request ${request.$id}`);
    }
  } catch (error) {
    logger.error(`Error in payout cron job: ${error.message}`);
  }
});

// Endpoints

// Image Upload Endpoint
app.post("/upload", verifyToken, upload.single("file"), (req, res) => {
  if (!req.file) {
    logger.warn("No file uploaded in /upload request");
    return res.status(400).json({ error: "No file uploaded" });
  }

  const fileUrl = `/uploads/${req.file.filename}`;
  logger.info(`File uploaded: ${fileUrl}`);
  res.status(200).json({ url: fileUrl });
});

// Location Suggestions
app.get("/api/locations", async (req, res) => {
  const { query } = req.query;

  if (!query) {
    logger.warn("Query parameter missing in /api/locations request");
    return res.status(400).json({ error: "Query parameter is required" });
  }

  try {
    const apiKey = process.env.GOOGLE_PLACES_API_KEY;
    if (!apiKey) {
      throw new Error("Google Places API key is missing");
    }

    const response = await fetch(
      `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(
        query
      )}&types=(cities)&key=${apiKey}`
    );

    if (!response.ok) {
      throw new Error(`Google Places API request failed: ${response.statusText}`);
    }

    const data = await response.json();
    if (data.status !== "OK") {
      throw new Error(`Google Places API error: ${data.status}`);
    }

    const suggestions = data.predictions.map((prediction) => ({
      name: prediction.structured_formatting.main_text,
      country: prediction.structured_formatting.secondary_text || "",
    }));

    res.status(200).json(suggestions);
  } catch (error) {
    logger.error(`Error fetching location suggestions: ${error.message}`);
    res.status(500).json({ error: error.message || "Failed to fetch location suggestions" });
  }
});

// User Signup
app.post("/signup", async (req, res) => {
  const { email, password, full_name } = req.body;
  if (!email || !password || !full_name) {
    logger.warn("Missing required fields in /signup request");
    return res.status(400).json({ error: "Missing email, password, or full_name" });
  }

  if (await isDisposableEmail(email)) {
    logger.warn(`Disposable email attempt: ${email}`);
    return res.status(400).json({ error: "Disposable email not allowed" });
  }

  const domain = email.split("@")[1];
  if (!(await checkMxRecord(domain))) {
    logger.warn(`Invalid email domain: ${domain}`);
    return res.status(400).json({ error: "Invalid email domain" });
  }

  let user = null;
  try {
    user = await account.create(ID.unique(), email, password, full_name);

    await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user.$id,
      { email, full_name, available: false, created_at: new Date().toISOString() },
      [
        `read("user:${user.$id}")`,
        `write("user:${user.$id}")`,
        `update("user:${user.$id}")`,
        `delete("user:${user.$id}")`,
        `read("users")`,
      ]
    );

    const token = generateToken(user.$id, email);
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.status(201).json({ message: "User registered successfully", user_id: user.$id });
  } catch (error) {
    if (user) {
      try {
        await account.delete(user.$id);
        logger.info(`Deleted user ${user.$id} due to error during signup`);
      } catch (deleteError) {
        logger.error(`Failed to delete user ${user.$id}: ${deleteError.message}`);
      }
    }
    logger.error(`Error during signup for email ${email}: ${error.message}`);
    res.status(400).json({ error: error.message || "Failed to create account" });
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password, rememberMe } = req.body;

  if (!email || !password) {
    logger.warn("Missing email or password in /login request");
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const session = await account.createEmailSession(email, password);
    const user = await account.get();

    const token = generateToken(user.$id, email);
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 30 days or 1 day
    });

    res.status(200).json({ user_id: user.$id, email: user.email });
  } catch (error) {
    logger.error(`Error during login for email ${email}: ${error.message}`);
    res.status(401).json({ error: "Invalid email or password" });
  }
});

// User Profile
app.get("/user-profile/:user_id", verifyToken, async (req, res) => {
  const { user_id } = req.params;
  if (req.user.id !== user_id) {
    logger.warn(`Unauthorized profile access attempt by user ${req.user.id} for user ${user_id}`);
    return res.status(403).json({ error: "Unauthorized" });
  }
  try {
    const user = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id
    );
    res.status(200).json({
      id: user.$id,
      email: user.email,
      full_name: user.full_name,
      phone_number: user.phone_number,
      location: user.location,
      bio: user.bio,
      avatar: user.avatar,
      available: user.available,
      kyc_document_url: user.kyc_document_url,
    });
  } catch (error) {
    logger.error(`Error fetching user profile for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch user profile" });
  }
});

app.put("/user-profile/:user_id", verifyToken, async (req, res) => {
  const { user_id } = req.params;
  const { full_name, phone_number, location, bio, available } = req.body;

  if (req.user.id !== user_id) {
    logger.warn(`Unauthorized profile update attempt by user ${req.user.id} for user ${user_id}`);
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const updatedUser = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id,
      { full_name, phone_number, location, bio, available },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json(updatedUser);
  } catch (error) {
    logger.error(`Error updating user profile for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to update user profile" });
  }
});

app.post("/user-profile/:user_id/avatar", verifyToken, upload.single("avatar"), async (req, res) => {
  const { user_id } = req.params;

  if (req.user.id !== user_id) {
    logger.warn(`Unauthorized avatar upload attempt by user ${req.user.id} for user ${user_id}`);
    return res.status(403).json({ error: "Unauthorized" });
  }

  if (!req.file) {
    logger.warn("No avatar file uploaded");
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id,
      { avatar: fileUrl },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ avatar_url: fileUrl });
  } catch (error) {
    logger.error(`Error uploading avatar for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to upload avatar" });
  }
});

// KYC Document Upload
app.post("/kyc", verifyToken, upload.single("kyc_document"), async (req, res) => {
  const { user_id } = req.body;

  if (!user_id || !req.file) {
    logger.warn("Missing user_id or kyc_document in /kyc request");
    return res.status(400).json({ error: "Missing user_id or kyc_document" });
  }

  if (req.user.id !== user_id) {
    logger.warn(`Unauthorized KYC upload attempt by user ${req.user.id} for user ${user_id}`);
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id,
      { kyc_document_url: fileUrl },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "KYC document uploaded", kyc_document_url: fileUrl });
  } catch (error) {
    logger.error(`Error uploading KYC document for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to upload KYC document" });
  }
});

// Create Shopping Request
app.post("/shopping-requests", verifyToken, async (req, res) => {
  const {
    requester_id,
    product_name,
    category,
    price,
    seller_location,
    required_by,
    description,
    product_url,
    delivery_instructions,
    reward,
    image_url,
  } = req.body;

  if (
    !requester_id ||
    !product_name ||
    !category ||
    !price ||
    !seller_location ||
    !required_by ||
    !reward
  ) {
    logger.warn("Missing required fields in /shopping-requests request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== requester_id) {
    logger.warn(
      `Unauthorized shopping request creation attempt by user ${req.user.id} for user ${requester_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  if (!isValidFutureDate(required_by)) {
    logger.warn(`Invalid required_by date: ${required_by}`);
    return res.status(400).json({ error: "Required by date must be a future date within 6 months" });
  }

  try {
    const user = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      requester_id
    );
    if (!user.kyc_document_url) {
      logger.warn(`KYC not completed for user ${requester_id}`);
      return res.status(403).json({ error: "KYC verification required" });
    }

    const document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      ID.unique(),
      {
        requester_id,
        product_name,
        category,
        price: parseFloat(price),
        seller_location,
        required_by: new Date(required_by).toISOString(),
        description,
        product_url,
        delivery_instructions,
        reward: parseFloat(reward),
        image_url,
        status: "pending",
        created_at: new Date().toISOString(),
      },
      [
        `read("user:${requester_id}")`,
        `write("user:${requester_id}")`,
        `update("user:${requester_id}")`,
        `delete("user:${requester_id}")`,
        `read("users")`,
      ]
    );

    res.status(201).json({ message: "Shopping request created", request_id: document.$id });
  } catch (error) {
    logger.error(`Error creating shopping request for user ${requester_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to create shopping request" });
  }
});

// Fetch All Shopping Requests
app.get("/shopping-requests", async (req, res) => {
  const { search, origin, destination, page = 1, pageSize = 12 } = req.query;

  try {
    const pageNum = parseInt(page, 10);
    const pageSizeNum = parseInt(pageSize, 10);
    const skip = (pageNum - 1) * pageSizeNum;

    let queries = [Query.equal("status", "pending")];

    if (search) {
      queries.push(
        Query.or([
          Query.search("product_name", search),
          Query.search("category", search),
        ])
      );
    }

    if (origin) {
      queries.push(Query.search("seller_location", origin));
    }

    // Note: Destination filter might require joining with user data to get the requester's location
    // For simplicity, we're not implementing it here, but you can add it based on your schema
    if (destination) {
      // Example: Join with user table to filter by requester's location
    }

    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      queries,
      pageSizeNum,
      skip,
      undefined,
      ["created_at DESC"]
    );

    res.status(200).json({ shopping_requests: response.documents });
  } catch (error) {
    logger.error(`Error fetching shopping requests: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch shopping requests" });
  }
});

// Fetch User's Shopping Requests
app.get("/my-shopping-requests/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) {
    logger.warn(
      `Unauthorized shopping requests fetch attempt by user ${req.user.id} for user ${userId}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      [Query.equal("requester_id", userId)]
    );
    res.status(200).json({ shopping_requests: response.documents });
  } catch (error) {
    logger.error(`Error fetching shopping requests for user ${userId}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch shopping requests" });
  }
});

// Post Travel Itinerary
app.post("/travel-itineraries", verifyToken, async (req, res) => {
  const {
    traveler_id,
    from_location,
    to_location,
    departure_date,
    arrival_date,
    available_space,
    preferred_items,
    available,
  } = req.body;

  if (!traveler_id || !from_location || !to_location || !departure_date || !arrival_date) {
    logger.warn("Missing required fields in /travel-itineraries request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== traveler_id) {
    logger.warn(
      `Unauthorized travel itinerary creation attempt by user ${req.user.id} for user ${traveler_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  if (!isValidFutureDate(departure_date) || !isValidFutureDate(arrival_date)) {
    logger.warn(`Invalid dates in travel itinerary: ${departure_date}, ${arrival_date}`);
    return res.status(400).json({ error: "Dates must be in the future and within 6 months" });
  }

  try {
    const user = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      traveler_id
    );
    if (!user.kyc_document_url) {
      logger.warn(`KYC not completed for user ${traveler_id}`);
      return res.status(403).json({ error: "KYC verification required" });
    }

    const existingItinerary = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      [
        Query.equal("traveler_id", traveler_id),
        Query.equal("from_location", from_location),
        Query.equal("to_location", to_location),
        Query.equal("departure_date", new Date(departure_date).toISOString()),
      ]
    );

    if (existingItinerary.total > 0) {
      logger.warn(`Duplicate travel itinerary for user ${traveler_id}`);
      return res.status(409).json({ error: "Duplicate itinerary exists" });
    }

    const itinerary = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      ID.unique(),
      {
        traveler_id,
        from_location,
        to_location,
        departure_date: new Date(departure_date).toISOString(),
        arrival_date: new Date(arrival_date).toISOString(),
        available_space: available_space ? parseInt(available_space) : null,
        preferred_items,
        available: available ?? true,
        status: "active",
        created_at: new Date().toISOString(),
      },
      [
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );

    res.status(201).json({ message: "Travel itinerary created", itinerary });
  } catch (error) {
    logger.error(`Error creating travel itinerary for user ${traveler_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to create travel itinerary" });
  }
});

app.patch("/travel-itineraries/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    logger.warn("Missing status in /travel-itineraries/:id request");
    return res.status(400).json({ error: "Status is required" });
  }

  try {
    const itinerary = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      id
    );

    if (itinerary.traveler_id !== req.user.id) {
      logger.warn(
        `Unauthorized travel itinerary update attempt by user ${req.user.id} for itinerary ${id}`
      );
      return res.status(403).json({ error: "Unauthorized" });
    }

    const updatedItinerary = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      id,
      { status },
      [
        `read("user:${itinerary.traveler_id}")`,
        `write("user:${itinerary.traveler_id}")`,
        `update("user:${itinerary.traveler_id}")`,
        `delete("user:${itinerary.traveler_id}")`,
        `read("users")`,
      ]
    );

    res.status(200).json({ message: "Itinerary updated", itinerary: updatedItinerary });
  } catch (error) {
    logger.error(`Error updating travel itinerary ${id}: ${error.message}`);
    res.status(500).json({ error: "Failed to update itinerary" });
  }
});

// Fetch User's Travel Itineraries
app.get("/travel-itineraries/user/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;

  if (req.user.id !== userId) {
    logger.warn(
      `Unauthorized travel itineraries fetch attempt by user ${req.user.id} for user ${userId}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const itineraries = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      [Query.equal("traveler_id", userId)]
    );
    res.status(200).json({ travel_itineraries: itineraries.documents });
  } catch (error) {
    logger.error(`Error fetching travel itineraries for user ${userId}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch itineraries" });
  }
});

// Send Chat Message
app.post("/send-message", verifyToken, async (req, res) => {
  const { sender_id, receiver_id, content } = req.body;
  if (!sender_id || !receiver_id || !content) {
    logger.warn("Missing required fields in /send-message request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== sender_id) {
    logger.warn(
      `Unauthorized message send attempt by user ${req.user.id} as sender ${sender_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  let document = null;
  try {
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_MESSAGES_COLLECTION_ID,
      ID.unique(),
      { sender_id, receiver_id, content, created_at: new Date().toISOString() },
      [
        `read("user:${sender_id}")`,
        `write("user:${sender_id}")`,
        `update("user:${sender_id}")`,
        `delete("user:${sender_id}")`,
        `read("user:${receiver_id}")`,
        `write("user:${receiver_id}")`,
        `update("user:${receiver_id}")`,
        `delete("user:${receiver_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(receiver_id, `New message from user ${sender_id}: ${content}`);
    res.status(200).json({ message: "Message sent", data: document });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_MESSAGES_COLLECTION_ID,
          document.$id
        );
        logger.info(`Deleted message ${document.$id} due to error`);
      } catch (deleteError) {
        logger.error(`Failed to delete message ${document.$id}: ${deleteError.message}`);
      }
    }
    logger.error(`Error sending message from ${sender_id} to ${receiver_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Fetch Chat History
app.get("/chat-history", verifyToken, async (req, res) => {
  const { user1, user2 } = req.query;
  if (!user1 || !user2) {
    logger.warn("Missing user1 or user2 in /chat-history request");
    return res.status(400).json({ error: "Missing user1 or user2 parameter" });
  }

  if (req.user.id !== user1 && req.user.id !== user2) {
    logger.warn(
      `Unauthorized chat history fetch attempt by user ${req.user.id} for users ${user1} and ${user2}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_MESSAGES_COLLECTION_ID,
      [
        Query.or([
          Query.and([Query.equal("sender_id", user1), Query.equal("receiver_id", user2)]),
          Query.and([Query.equal("sender_id", user2), Query.equal("receiver_id", user1)]),
        ]),
      ]
    );
    res.status(200).json({ chat: response.documents });
  } catch (error) {
    logger.error(`Error fetching chat history for users ${user1} and ${user2}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch chat history" });
  }
});

// Post Review
app.post("/post-review", verifyToken, async (req, res) => {
  const { reviewer_id, reviewee_id, rating, comment } = req.body;
  if (!reviewer_id || !reviewee_id || !rating) {
    logger.warn("Missing required fields in /post-review request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== reviewer_id) {
    logger.warn(
      `Unauthorized review post attempt by user ${req.user.id} as reviewer ${reviewer_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  if (rating < 1 || rating > 5) {
    logger.warn(`Invalid rating value: ${rating}`);
    return res.status(400).json({ error: "Rating must be between 1 and 5" });
  }

  let document = null;
  try {
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_REVIEWS_COLLECTION_ID,
      ID.unique(),
      { reviewer_id, reviewee_id, rating, comment, created_at: new Date().toISOString() },
      [
        `read("user:${reviewer_id}")`,
        `write("user:${reviewer_id}")`,
        `update("user:${reviewer_id}")`,
        `delete("user:${reviewer_id}")`,
        `read("user:${reviewee_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Review submitted", review_id: document.$id });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_REVIEWS_COLLECTION_ID,
          document.$id
        );
        logger.info(`Deleted review ${document.$id} due to error`);
      } catch (deleteError) {
        logger.error(`Failed to delete review ${document.$id}: ${deleteError.message}`);
      }
    }
    logger.error(`Error posting review by user ${reviewer_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to submit review" });
  }
});

// Fetch User Reviews
app.get("/user-reviews/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_REVIEWS_COLLECTION_ID,
      [Query.equal("reviewee_id", user_id)]
    );
    res.status(200).json({ reviews: response.documents });
  } catch (error) {
    logger.error(`Error fetching reviews for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch reviews" });
  }
});

// Traveler Ranking
app.get("/traveler-ranking/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const reviews = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_REVIEWS_COLLECTION_ID,
      [Query.equal("reviewee_id", user_id)]
    );
    const avgRating = reviews.documents.length
      ? reviews.documents.reduce((sum, r) => sum + r.rating, 0) / reviews.documents.length
      : 0;
    res.status(200).json({
      user_id,
      average_rating: avgRating,
      review_count: reviews.documents.length,
    });
  } catch (error) {
    logger.error(`Error fetching traveler ranking for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch traveler ranking" });
  }
});

// Suggest Travelers
app.get("/suggest-travelers/:request_id", verifyToken, async (req, res) => {
  const { request_id } = req.params;
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    if (req.user.id !== request.requester_id) {
      logger.warn(
        `Unauthorized traveler suggestion fetch attempt by user ${req.user.id} for request ${request_id}`
      );
      return res.status(403).json({ error: "Unauthorized" });
    }

    const itineraries = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      [Query.equal("available", true)]
    );

    const matches = itineraries.documents
      .map((itinerary) => {
        const score =
          (itinerary.from_location.toLowerCase().includes(request.seller_location.toLowerCase())
            ? 50
            : 0) +
          (new Date(itinerary.departure_date) <= new Date(request.required_by) ? 30 : 0) +
          (itinerary.available_space >= 1 ? 20 : 0);
        return { ...itinerary, match_score: score };
      })
      .sort((a, b) => b.match_score - a.match_score);

    res.status(200).json({ suggested_travelers: matches.slice(0, 5) });
  } catch (error) {
    logger.error(`Error suggesting travelers for request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to suggest travelers" });
  }
});

// Set Traveler Availability
app.post("/set-availability", verifyToken, async (req, res) => {
  const { user_id, available } = req.body;
  if (!user_id || typeof available !== "boolean") {
    logger.warn("Missing or invalid fields in /set-availability request");
    return res.status(400).json({ error: "Missing or invalid user_id or available field" });
  }

  if (req.user.id !== user_id) {
    logger.warn(
      `Unauthorized availability update attempt by user ${req.user.id} for user ${user_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id,
      { available },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: `Availability set to ${available}` });
  } catch (error) {
    logger.error(`Error setting availability for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to set availability" });
  }
});

// Confirm Delivery
app.post("/confirm-delivery", verifyToken, async (req, res) => {
  const { request_id, traveler_id } = req.body;
  if (!request_id || !traveler_id) {
    logger.warn("Missing required fields in /confirm-delivery request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== traveler_id) {
    logger.warn(
      `Unauthorized delivery confirmation attempt by user ${req.user.id} for traveler ${traveler_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );

    if (request.status !== "accepted") {
      logger.warn(`Invalid request status for delivery confirmation: ${request.status}`);
      return res.status(400).json({ error: "Request must be in accepted state" });
    }

    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { status: "delivered", updated_at: new Date().toISOString() },
      [
        `read("user:${request.requester_id}")`,
        `write("user:${request.requester_id}")`,
        `update("user:${request.requester_id}")`,
        `delete("user:${request.requester_id}")`,
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(
      request.requester_id,
      `Your request ${request_id} has been marked as delivered`
    );
    res.status(200).json({ message: "Delivery confirmed, payment scheduled for auto-release" });
  } catch (error) {
    logger.error(`Error confirming delivery for request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to confirm delivery" });
  }
});

// Create Razorpay Order
app.post("/create-payment", verifyToken, async (req, res) => {
  const { amount, shopper_id, currency = "INR" } = req.body;
  if (!amount || !shopper_id) {
    logger.warn("Missing required fields in /create-payment request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== shopper_id) {
    logger.warn(
      `Unauthorized payment creation attempt by user ${req.user.id} for shopper ${shopper_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  const options = { amount: amount * 100, currency, receipt: `order_rcptid_${Date.now()}` };

  let order = null;
  let document = null;
  try {
    order = await razorpay.orders.create(options);
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
      ID.unique(),
      { order_id: order.id, shopper_id, amount, currency, status: "pending" },
      [
        `read("user:${shopper_id}")`,
        `write("user:${shopper_id}")`,
        `update("user:${shopper_id}")`,
        `delete("user:${shopper_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ order_id: order.id });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
          document.$id
        );
        logger.info(`Deleted payment ${document.$id} due to error`);
      } catch (deleteError) {
        logger.error(`Failed to delete payment ${document.$id}: ${deleteError.message}`);
      }
    }
    logger.error(`Error creating payment for user ${shopper_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to create payment" });
  }
});

// Capture Razorpay Payment
app.post("/capture-payment", verifyToken, async (req, res) => {
  const { payment_id, amount, currency = "INR" } = req.body;
  if (!payment_id || !amount) {
    logger.warn("Missing required fields in /capture-payment request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const payment = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
      [Query.equal("order_id", payment_id)]
    );

    if (!payment.documents.length) {
      logger.warn(`Payment not found for payment_id ${payment_id}`);
      return res.status(404).json({ error: "Payment not found" });
    }

    const paymentDoc = payment.documents[0];
    if (req.user.id !== paymentDoc.shopper_id) {
      logger.warn(
        `Unauthorized payment capture attempt by user ${req.user.id} for payment ${payment_id}`
      );
      return res.status(403).json({ error: "Unauthorized" });
    }

    const response = await fetch(`https://api.razorpay.com/v1/payments/${payment_id}/capture`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${Buffer.from(
          `${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`
        ).toString("base64")}`,
      },
      body: JSON.stringify({ amount: amount * 100, currency }),
    });

    const captureResult = await response.json();
    if (captureResult.error) {
      logger.warn(`Razorpay capture error: ${captureResult.error.description}`);
      return res.status(400).json({ error: captureResult.error.description });
    }

    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
      paymentDoc.$id,
      { status: "captured" },
      [
        `read("user:${paymentDoc.shopper_id}")`,
        `write("user:${paymentDoc.shopper_id}")`,
        `update("user:${paymentDoc.shopper_id}")`,
        `delete("user:${paymentDoc.shopper_id}")`,
        `read("users")`,
      ]
    );

    res.status(200).json({ message: "Payment captured successfully" });
  } catch (error) {
    logger.error(`Error capturing payment for payment_id ${payment_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to capture payment" });
  }
});

// Manual Payout
app.post("/auto-release-payment", verifyToken, async (req, res) => {
  const { traveler_account_id, amount, currency = "INR" } = req.body;
  if (!traveler_account_id || !amount) {
    logger.warn("Missing required fields in /auto-release-payment request");
    return res.status(400).json({ error: "Missing traveler_account_id or amount" });
  }

  try {
    const transfer = await razorpay.transfers.create({
      account: traveler_account_id,
      amount: amount * 100,
      currency,
      notes: { purpose: "Manual Escrow Release" },
    });

    await sendNotification(
      traveler_account_id,
      `Manual payment of INR ${amount} has been released`
    );
    res.status(200).json({ message: "Payment released manually", transfer });
  } catch (error) {
    logger.error(
      `Error releasing payment for traveler ${traveler_account_id}: ${error.message}`
    );
    res.status(500).json({ error: "Failed to release payment" });
  }
});

// Create Match
app.post("/matches", verifyToken, async (req, res) => {
  const { request_id, traveler_id } = req.body;
  if (!request_id || !traveler_id) {
    logger.warn("Missing required fields in /matches request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== traveler_id) {
    logger.warn(
      `Unauthorized match creation attempt by user ${req.user.id} for traveler ${traveler_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );

    const existingMatch = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_MATCHES_COLLECTION_ID,
      [Query.equal("request_id", request_id), Query.equal("traveler_id", traveler_id)]
    );

    if (existingMatch.total > 0) {
      logger.warn(`Duplicate match for request ${request_id} and traveler ${traveler_id}`);
      return res.status(409).json({ error: "Match already exists" });
    }

    const document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_MATCHES_COLLECTION_ID,
      ID.unique(),
      { request_id, traveler_id, created_at: new Date().toISOString() },
      [
        `read("user:${request.requester_id}")`,
        `write("user:${request.requester_id}")`,
        `update("user:${request.requester_id}")`,
        `delete("user:${request.requester_id}")`,
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(
      request.requester_id,
      `Traveler ${traveler_id} has shown interest in your request ${request_id}`
    );
    res.status(200).json({ request_id: document.request_id, traveler_id: document.traveler_id });
  } catch (error) {
    logger.error(`Error creating match for request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to create match" });
  }
});

// Accept Request
app.post("/accept-request", verifyToken, async (req, res) => {
  const { request_id, traveler_id } = req.body;
  if (!request_id || !traveler_id) {
    logger.warn("Missing required fields in /accept-request request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== traveler_id) {
    logger.warn(
      `Unauthorized request acceptance attempt by user ${req.user.id} for traveler ${traveler_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );

    if (request.status !== "pending") {
      logger.warn(`Invalid request status for acceptance: ${request.status}`);
      return res.status(400).json({ error: "Request must be in pending state" });
    }

    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { status: "accepted", traveler_id },
      [
        `read("user:${request.requester_id}")`,
        `write("user:${request.requester_id}")`,
        `update("user:${request.requester_id}")`,
        `delete("user:${request.requester_id}")`,
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(request.requester_id, "Your request has been accepted!");
    res.status(200).json({ message: "Request accepted" });
  } catch (error) {
    logger.error(`Error accepting request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to accept request" });
  }
});

// Fetch Notifications
app.get("/notifications/:user_id", verifyToken, async (req, res) => {
  const { user_id } = req.params;
  if (req.user.id !== user_id) {
    logger.warn(
      `Unauthorized notifications fetch attempt by user ${req.user.id} for user ${user_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_NOTIFICATIONS_COLLECTION_ID,
      [Query.equal("user_id", user_id)]
    );
    res.status(200).json(response.documents);
  } catch (error) {
    logger.error(`Error fetching notifications for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// Fetch User Transactions
app.get("/user-transactions/:user_id", verifyToken, async (req, res) => {
  const { user_id } = req.params;
  if (req.user.id !== user_id) {
    logger.warn(
      `Unauthorized transactions fetch attempt by user ${req.user.id} for user ${user_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
      [Query.equal("shopper_id", user_id)]
    );
    res.status(200).json({ transactions: response.documents });
  } catch (error) {
    logger.error(`Error fetching transactions for user ${user_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// Upload Proof of Purchase
app.post("/upload-proof-of-purchase", verifyToken, upload.single("proof_file"), async (req, res) => {
  const { request_id } = req.body;
  if (!request_id || !req.file) {
    logger.warn("Missing request_id or proof_file in /upload-proof-of-purchase request");
    return res.status(400).json({ error: "Missing request_id or proof_file" });
  }

  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );

    if (req.user.id !== request.requester_id) {
      logger.warn(
        `Unauthorized proof of purchase upload attempt by user ${req.user.id} for request ${request_id}`
      );
      return res.status(403).json({ error: "Unauthorized" });
    }

    const fileUrl = `/uploads/${req.file.filename}`;
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { proof_of_purchase_url: fileUrl },
      [
        `read("user:${request.requester_id}")`,
        `write("user:${request.requester_id}")`,
        `update("user:${request.requester_id}")`,
        `delete("user:${request.requester_id}")`,
        `read("user:${request.traveler_id}")`,
        `write("user:${request.traveler_id}")`,
        `update("user:${request.traveler_id}")`,
        `delete("user:${request.traveler_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(
      request.traveler_id,
      `Proof of purchase uploaded for request ${request_id}`
    );
    res.status(200).json({ message: "Proof of purchase uploaded", file_url: fileUrl });
  } catch (error) {
    logger.error(`Error uploading proof of purchase for request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to upload proof of purchase" });
  }
});

// Upload Delivery Proof
app.post("/upload-delivery-proof", verifyToken, upload.single("proof_photo"), async (req, res) => {
  const { request_id } = req.body;
  if (!request_id || !req.file) {
    logger.warn("Missing request_id or proof_photo in /upload-delivery-proof request");
    return res.status(400).json({ error: "Missing request_id or proof_photo" });
  }

  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );

    if (req.user.id !== request.traveler_id) {
      logger.warn(
        `Unauthorized delivery proof upload attempt by user ${req.user.id} for request ${request_id}`
      );
      return res.status(403).json({ error: "Unauthorized" });
    }

    const fileUrl = `/uploads/${req.file.filename}`;
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { proof_photo_url: fileUrl, status: "completed" },
      [
        `read("user:${request.requester_id}")`,
        `write("user:${request.requester_id}")`,
        `update("user:${request.requester_id}")`,
        `delete("user:${request.requester_id}")`,
        `read("user:${request.traveler_id}")`,
        `write("user:${request.traveler_id}")`,
        `update("user:${request.traveler_id}")`,
        `delete("user:${request.traveler_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(
      request.requester_id,
      `Delivery proof uploaded for request ${request_id}`
    );
    res.status(200).json({ message: "Delivery proof uploaded", file_url: fileUrl });
  } catch (error) {
    logger.error(`Error uploading delivery proof for request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to upload delivery proof" });
  }
});

// Raise Dispute
app.post("/raise-dispute", verifyToken, async (req, res) => {
  const { request_id, user_id, reason } = req.body;
  if (!request_id || !user_id || !reason) {
    logger.warn("Missing required fields in /raise-dispute request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (req.user.id !== user_id) {
    logger.warn(
      `Unauthorized dispute raise attempt by user ${req.user.id} for user ${user_id}`
    );
    return res.status(403).json({ error: "Unauthorized" });
  }

  let document = null;
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );

    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DISPUTES_COLLECTION_ID,
      ID.unique(),
      { request_id, user_id, reason, status: "open", created_at: new Date().toISOString() },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("user:${request.requester_id}")`,
        `read("user:${request.traveler_id}")`,
        `read("users")`,
      ]
    );

    res.status(200).json({ message: "Dispute raised", dispute_id: document.$id });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_DISPUTES_COLLECTION_ID,
          document.$id
        );
        logger.info(`Deleted dispute ${document.$id} due to error`);
      } catch (deleteError) {
        logger.error(`Failed to delete dispute ${document.$id}: ${deleteError.message}`);
      }
    }
    logger.error(`Error raising dispute for request ${request_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to raise dispute" });
  }
});

// Admin Endpoints
app.get("/admin/all-shopping-requests", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      []
    );
    res.status(200).json({ all_requests: response.documents });
  } catch (error) {
    logger.error(`Error fetching all shopping requests for admin: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch shopping requests" });
  }
});

app.get("/admin/incomplete-traveler-profiles", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      [Query.equal("phone_number", null)]
    );
    const incompleteProfiles = response.documents.map((user) => ({
      id: user.$id,
      full_name: user.full_name,
      email: user.email,
    }));
    res.status(200).json({ incomplete_profiles: incompleteProfiles });
  } catch (error) {
    logger.error(`Error fetching incomplete traveler profiles for admin: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch incomplete profiles" });
  }
});

app.get("/admin/disputes", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DISPUTES_COLLECTION_ID,
      []
    );
    res.status(200).json({ disputes: response.documents });
  } catch (error) {
    logger.error(`Error fetching disputes for admin: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch disputes" });
  }
});

app.post("/admin/resolve-dispute", verifyToken, verifyAdmin, async (req, res) => {
  const { dispute_id, resolution_notes } = req.body;
  if (!dispute_id || !resolution_notes) {
    logger.warn("Missing required fields in /admin/resolve-dispute request");
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const dispute = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DISPUTES_COLLECTION_ID,
      dispute_id
    );

    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DISPUTES_COLLECTION_ID,
      dispute_id,
      { status: "resolved", resolution_notes },
      [
        `read("user:${dispute.user_id}")`,
        `write("user:${dispute.user_id}")`,
        `update("user:${dispute.user_id}")`,
        `delete("user:${dispute.user_id}")`,
        `read("user:${dispute.shopper_id}")`,
        `read("user:${dispute.traveler_id}")`,
        `read("users")`,
      ]
    );

    await sendNotification(dispute.user_id, `Dispute ${dispute_id} has been resolved`);
    res.status(200).json({ message: "Dispute resolved" });
  } catch (error) {
    logger.error(`Error resolving dispute ${dispute_id}: ${error.message}`);
    res.status(500).json({ error: "Failed to resolve dispute" });
  }
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.get("/", (req, res) => {
  res.redirect("/api-docs");
});

app.listen(PORT, "0.0.0.0", () => {
  logger.info(`✅ Backend running on port ${PORT} on 0.0.0.0`);
});