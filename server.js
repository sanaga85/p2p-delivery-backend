require("dotenv").config();
const express = require("express");
const cors = require("cors");
const dns = require("dns");
const { Client, Account, Databases, Storage, ID, Query } = require("node-appwrite");
const Razorpay = require("razorpay");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const swaggerDocument = YAML.load("./swagger.yaml");
const cron = require("node-cron");
const admin = require("firebase-admin");
const multer = require("multer");

// Initialize Express and Middleware
const app = express();

const corsOptions = {
  origin: "https://reimagined-goggles-wr57v7pvq5p6fvg9r-5000.app.github.dev",
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

// Set up multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });
app.use(upload.any());

// Serve Swagger UI
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Initialize Appwrite Client
const client = new Client()
  .setEndpoint(process.env.APPWRITE_ENDPOINT)
  .setProject(process.env.APPWRITE_PROJECT_ID)
  .setKey(process.env.APPWRITE_API_KEY);

const account = new Account(client);
const databases = new Databases(client);
const storage = new Storage(client);

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Initialize Firebase for Push Notifications
const serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

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
    }
  } catch (error) {
    console.error("Error sending push notification:", error.message);
  }
};

// Utility Functions
async function isDisposableEmail(email) {
  try {
    const { default: fetch } = await import("node-fetch");
    const response = await fetch(`https://disify.com/api/email/${email}`);
    const data = await response.json();
    return data.disposable;
  } catch (error) {
    return false;
  }
}

function checkMxRecord(domain) {
  return new Promise((resolve) => {
    dns.resolveMx(domain, (err, addresses) => {
      resolve(!err && addresses && addresses.length > 0);
    });
  });
}

function isValidFutureDate(dateStr) {
  const inputDate = new Date(dateStr);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const sixMonthsLater = new Date();
  sixMonthsLater.setMonth(today.getMonth() + 6);
  return inputDate >= today && inputDate <= sixMonthsLater;
}

async function sendNotification(userId, message) {
  try {
    await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_NOTIFICATIONS_COLLECTION_ID,
      ID.unique(),
      { user_id: userId, message },
      [
        `read("user:${userId}")`,
        `write("user:${userId}")`,
        `update("user:${userId}")`,
        `delete("user:${userId}")`,
        `read("users")`,
      ]
    );
    await sendPushNotification(userId, "New Notification", message);
  } catch (error) {
    console.error("Error sending notification:", error.message);
    throw error; // Re-throw to allow rollback in calling functions
  }
}

// Traveler Profile Completion Reminder (Cron Job - Daily at Midnight)
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
  } catch (error) {
    console.error("Error in profile completion cron job:", error.message);
  }
});

// Automated Payout Scheduling (Cron Job - Every Hour)
cron.schedule("0 * * * *", async () => {
  try {
    const requests = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      [Query.equal("status", "delivered")]
    );
    for (const request of requests.documents) {
      await razorpay.transfers.create({
        account: request.traveler_id,
        amount: request.price * 100,
        currency: "INR",
        notes: { purpose: "Automated Escrow Release" },
      });
      await databases.updateDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
        request.$id,
        { status: "paid" },
        [
          `read("user:${request.shopper_id}")`,
          `write("user:${request.shopper_id}")`,
          `update("user:${request.shopper_id}")`,
          `delete("user:${request.shopper_id}")`,
          `read("user:${request.traveler_id}")`,
          `write("user:${request.traveler_id}")`,
          `update("user:${request.traveler_id}")`,
          `delete("user:${request.traveler_id}")`,
          `read("users")`,
        ]
      );
    }
  } catch (error) {
    console.error("Error in payout cron job:", error.message);
  }
});

// Endpoints

// ✅ Manual Payout Endpoint
app.post("/auto-release-payment", async (req, res) => {
  const { traveler_account_id, amount, currency = "INR" } = req.body;
  if (!traveler_account_id || !amount) {
    return res.status(400).json({ error: "Missing traveler_account_id or amount" });
  }
  try {
    const transfer = await razorpay.transfers.create({
      account: traveler_account_id,
      amount: amount * 100,
      currency,
      notes: { purpose: "Manual Escrow Release" },
    });
    res.status(200).json({ message: "Payment released manually", transfer });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Traveler Ranking Endpoint
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
    res.status(500).json({ error: error.message });
  }
});

// ✅ Advanced Traveler Suggestion with Scoring
app.get("/suggest-travelers/:request_id", async (req, res) => {
  const { request_id } = req.params;
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    const itineraries = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      [Query.equal("available", true)]
    );
    const matches = itineraries.documents.map((itinerary) => {
      const score =
        (itinerary.from_location.includes(request.seller_location) ? 50 : 0) +
        (new Date(itinerary.departure_date) <= new Date(request.required_by) ? 30 : 0) +
        (itinerary.available_space >= 1 ? 20 : 0);
      return { ...itinerary, match_score: score };
    }).sort((a, b) => b.match_score - a.match_score);
    res.status(200).json({ suggested_travelers: matches.slice(0, 5) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Set Traveler Availability
app.post("/set-availability", async (req, res) => {
  const { user_id, available } = req.body;
  if (!user_id || typeof available !== "boolean") {
    return res.status(400).json({ error: "Missing or invalid user_id or available field" });
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
    res.status(500).json({ error: error.message });
  }
});

// ✅ User Signup
app.post("/signup", async (req, res) => {
  const { email, password, full_name } = req.body;
  if (!email || !password || !full_name) {
    return res.status(400).json({ error: "Missing email, password, or full_name" });
  }
  if (await isDisposableEmail(email)) {
    return res.status(400).json({ error: "Disposable email not allowed" });
  }
  const domain = email.split("@")[1];
  if (!(await checkMxRecord(domain))) {
    return res.status(400).json({ error: "Invalid email domain" });
  }

  let user = null;
  try {
    // Step 1: Create the user in Appwrite's authentication system
    user = await account.create(ID.unique(), email, password, full_name);

    // Step 2: Create the user document in the database
    await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user.$id,
      { email, full_name, available: false },
      [
        `read("user:${user.$id}")`,
        `write("user:${user.$id}")`,
        `update("user:${user.$id}")`,
        `delete("user:${user.$id}")`,
        `read("users")`,
      ]
    );

    // Step 3: If everything succeeds, return success
    res.status(200).json({ message: "User registered successfully", user_id: user.$id });
  } catch (error) {
    // Step 4: If an error occurs, delete the user from Appwrite's authentication system
    if (user) {
      try {
        await account.delete(user.$id);
        console.log(`Deleted user ${user.$id} due to error during signup`);
      } catch (deleteError) {
        console.error(`Failed to delete user ${user.$id}:`, deleteError.message);
      }
    }
    res.status(400).json({ error: error.message });
  }
});

// ✅ User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }
  try {
    const session = await account.createEmailPasswordSession(email, password);
    res.status(200).json({ message: "Login successful", token: session.secret });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ✅ Google OAuth Login
app.post("/auth/google", async (req, res) => {
  try {
    const redirectUrl = process.env.GOOGLE_REDIRECT_URL || `${req.protocol}://${req.get("host")}/callback`;
    const url = await account.createOAuth2Session("google", redirectUrl, `${redirectUrl}/error`);
    res.status(200).json({ url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Facebook OAuth Login
app.post("/auth/facebook", async (req, res) => {
  try {
    const redirectUrl = process.env.FACEBOOK_REDIRECT_URL || `${req.protocol}://${req.get("host")}/callback`;
    const url = await account.createOAuth2Session("facebook", redirectUrl, `${redirectUrl}/error`);
    res.status(200).json({ url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch User Profile
app.get("/user-profile/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const user = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id
    );
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Create Shopping Request
app.post("/shopping-requests", async (req, res) => {
  const { shopper_id, product_name, category, price, seller_location, required_by } = req.body;
  if (!shopper_id || !product_name || !category || !price || !seller_location || !required_by) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (!isValidFutureDate(required_by)) {
    return res.status(400).json({ error: "Invalid date" });
  }

  let document = null;
  try {
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      ID.unique(),
      { shopper_id, product_name, category, price, seller_location, required_by, status: "pending" },
      [
        `read("user:${shopper_id}")`,
        `write("user:${shopper_id}")`,
        `update("user:${shopper_id}")`,
        `delete("user:${shopper_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Shopping request created", request_id: document.$id });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
          document.$id
        );
        console.log(`Deleted shopping request ${document.$id} due to error`);
      } catch (deleteError) {
        console.error(`Failed to delete shopping request ${document.$id}:`, deleteError.message);
      }
    }
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch All Shopping Requests
app.get("/shopping-requests", async (req, res) => {
  const { location, category } = req.query;
  let queries = [];
  if (location) queries.push(Query.search("seller_location", location));
  if (category) queries.push(Query.equal("category", category));
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      queries
    );
    res.status(200).json({ shopping_requests: response.documents });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Post Travel Itinerary
app.post("/travel-itineraries", async (req, res) => {
  const { traveler_id, from_location, to_location, departure_date, arrival_date, available_space, preferred_items } = req.body;
  if (!traveler_id || !from_location || !to_location || !departure_date || !arrival_date) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (!isValidFutureDate(departure_date) || !isValidFutureDate(arrival_date)) {
    return res.status(400).json({ error: "Invalid dates" });
  }

  let document = null;
  try {
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      ID.unique(),
      { traveler_id, from_location, to_location, departure_date, arrival_date, available_space, preferred_items, available: true },
      [
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Itinerary created", itinerary: document });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
          document.$id
        );
        console.log(`Deleted travel itinerary ${document.$id} due to error`);
      } catch (deleteError) {
        console.error(`Failed to delete travel itinerary ${document.$id}:`, deleteError.message);
      }
    }
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch User's Travel Itineraries
app.get("/my-travel-itineraries/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_TRAVEL_ITINERARIES_COLLECTION_ID,
      [Query.equal("traveler_id", user_id)]
    );
    res.status(200).json({ travel_itineraries: response.documents });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Send Chat Message
app.post("/send-message", async (req, res) => {
  const { sender_id, receiver_id, content } = req.body;
  if (!sender_id || !receiver_id || !content) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  let document = null;
  try {
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_MESSAGES_COLLECTION_ID,
      ID.unique(),
      { sender_id, receiver_id, content },
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

    await sendNotification(receiver_id, `New message from ${sender_id}: ${content}`);
    res.status(200).json({ message: "Message sent", data: document });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_MESSAGES_COLLECTION_ID,
          document.$id
        );
        console.log(`Deleted message ${document.$id} due to error`);
      } catch (deleteError) {
        console.error(`Failed to delete message ${document.$id}:`, deleteError.message);
      }
    }
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch Chat History
app.get("/chat-history", async (req, res) => {
  const { user1, user2 } = req.query;
  if (!user1 || !user2) {
    return res.status(400).json({ error: "Missing user1 or user2 parameter" });
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
    res.status(500).json({ error: error.message });
  }
});

// ✅ Post Review
app.post("/post-review", async (req, res) => {
  const { reviewer_id, reviewee_id, rating, comment } = req.body;
  if (!reviewer_id || !reviewee_id || !rating) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  let document = null;
  try {
    document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_REVIEWS_COLLECTION_ID,
      ID.unique(),
      { reviewer_id, reviewee_id, rating, comment },
      [
        `read("user:${reviewer_id}")`,
        `write("user:${reviewer_id}")`,
        `update("user:${reviewer_id}")`,
        `delete("user:${reviewer_id}")`,
        `read("user:${reviewee_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Review submitted" });
  } catch (error) {
    if (document) {
      try {
        await databases.deleteDocument(
          process.env.APPWRITE_DATABASE_ID,
          process.env.APPWRITE_REVIEWS_COLLECTION_ID,
          document.$id
        );
        console.log(`Deleted review ${document.$id} due to error`);
      } catch (deleteError) {
        console.error(`Failed to delete review ${document.$id}:`, deleteError.message);
      }
    }
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch User Reviews
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
    res.status(500).json({ error: error.message });
  }
});

// ✅ Confirm Delivery
app.post("/confirm-delivery", async (req, res) => {
  const { request_id, traveler_id, amount, currency = "INR" } = req.body;
  if (!request_id || !traveler_id || !amount) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { status: "delivered" },
      [
        `read("user:${request.shopper_id}")`,
        `write("user:${request.shopper_id}")`,
        `update("user:${request.shopper_id}")`,
        `delete("user:${request.shopper_id}")`,
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Delivery confirmed, payment scheduled for auto-release" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Create Razorpay Order
app.post("/create-payment", async (req, res) => {
  const { amount, shopper_id, currency = "INR" } = req.body;
  if (!amount || !shopper_id) {
    return res.status(400).json({ error: "Missing required fields" });
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
        console.log(`Deleted payment ${document.$id} due to error`);
      } catch (deleteError) {
        console.error(`Failed to delete payment ${document.$id}:`, deleteError.message);
      }
    }
    res.status(500).json({ error: error.message });
  }
});

// ✅ Capture Razorpay Payment
app.post("/capture-payment", async (req, res) => {
  const { payment_id, amount, currency = "INR" } = req.body;
  if (!payment_id || !amount) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  try {
    const { default: fetch } = await import("node-fetch");
    const response = await fetch(`https://api.razorpay.com/v1/payments/${payment_id}/capture`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString("base64")}`,
      },
      body: JSON.stringify({ amount: amount * 100, currency }),
    });
    const captureResult = await response.json();
    if (captureResult.error) {
      return res.status(400).json({ error: captureResult.error.description });
    }
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
      payment_id,
      { status: "captured" },
      [
        `read("user:${captureResult.shopper_id}")`,
        `write("user:${captureResult.shopper_id}")`,
        `update("user:${captureResult.shopper_id}")`,
        `delete("user:${captureResult.shopper_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Payment captured successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Create Match
app.post("/matches", async (req, res) => {
  const { request_id, traveler_id } = req.body;
  if (!request_id || !traveler_id) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    const document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_MATCHES_COLLECTION_ID,
      ID.unique(),
      { request_id, traveler_id },
      [
        `read("user:${request.shopper_id}")`,
        `write("user:${request.shopper_id}")`,
        `update("user:${request.shopper_id}")`,
        `delete("user:${request.shopper_id}")`,
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ request_id: document.request_id, traveler_id: document.traveler_id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Accept Request
app.post("/accept-request", async (req, res) => {
  const { request_id, traveler_id } = req.body;
  if (!request_id || !traveler_id) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  let request = null;
  try {
    request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { status: "accepted", traveler_id },
      [
        `read("user:${request.shopper_id}")`,
        `write("user:${request.shopper_id}")`,
        `update("user:${request.shopper_id}")`,
        `delete("user:${request.shopper_id}")`,
        `read("user:${traveler_id}")`,
        `write("user:${traveler_id}")`,
        `update("user:${traveler_id}")`,
        `delete("user:${traveler_id}")`,
        `read("users")`,
      ]
    );
    await sendNotification(request.shopper_id, "Your request has been accepted!");
    res.status(200).json({ message: "Request accepted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch Notifications
app.get("/notifications/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_NOTIFICATIONS_COLLECTION_ID,
      [Query.equal("user_id", user_id)]
    );
    res.status(200).json(response.documents);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Fetch User Transactions
app.get("/user-transactions/:user_id", async (req, res) => {
  const { user_id } = req.params;
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_PAYMENTS_COLLECTION_ID,
      [Query.equal("shopper_id", user_id)]
    );
    res.status(200).json({ transactions: response.documents });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Upload Proof of Purchase
app.post("/upload-proof-of-purchase", upload.single("proof_file"), async (req, res) => {
  const { request_id } = req.body;
  if (!request_id || !req.file) {
    return res.status(400).json({ error: "Missing request_id or proof_file" });
  }
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    const uploadedFile = await storage.createFile(
      process.env.APPWRITE_BUCKET_ID,
      ID.unique(),
      req.file.buffer,
      req.file.originalname
    );
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { proof_of_purchase_id: uploadedFile.$id },
      [
        `read("user:${request.shopper_id}")`,
        `write("user:${request.shopper_id}")`,
        `update("user:${request.shopper_id}")`,
        `delete("user:${request.shopper_id}")`,
        `read("user:${request.traveler_id}")`,
        `write("user:${request.traveler_id}")`,
        `update("user:${request.traveler_id}")`,
        `delete("user:${request.traveler_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Proof of purchase uploaded", file_id: uploadedFile.$id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Admin View All Shopping Requests
app.get("/admin/all-shopping-requests", async (req, res) => {
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      []
    );
    res.status(200).json({ all_requests: response.documents });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Admin View Incomplete Traveler Profiles
app.get("/admin/incomplete-traveler-profiles", async (req, res) => {
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
    res.status(500).json({ error: error.message });
  }
});

// ✅ Raise Dispute
app.post("/raise-dispute", async (req, res) => {
  const { request_id, user_id, reason } = req.body;
  if (!request_id || !user_id || !reason) {
    return res.status(400).json({ error: "Missing required fields" });
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
      { request_id, user_id, reason, status: "open" },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("user:${request.shopper_id}")`,
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
        console.log(`Deleted dispute ${document.$id} due to error`);
      } catch (deleteError) {
        console.error(`Failed to delete dispute ${document.$id}:`, deleteError.message);
      }
    }
    res.status(500).json({ error: error.message });
  }
});

// ✅ Admin View Disputes
app.get("/admin/disputes", async (req, res) => {
  try {
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DISPUTES_COLLECTION_ID,
      []
    );
    res.status(200).json({ disputes: response.documents });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Resolve Dispute
app.post("/admin/resolve-dispute", async (req, res) => {
  const { dispute_id, resolution_notes } = req.body;
  if (!dispute_id || !resolution_notes) {
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
    res.status(200).json({ message: "Dispute resolved" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Upload KYC Document
app.post("/upload-kyc", upload.single("kyc_document"), async (req, res) => {
  const { user_id } = req.body;
  if (!user_id || !req.file) {
    return res.status(400).json({ error: "Missing user_id or kyc_document" });
  }
  try {
    const uploadedFile = await storage.createFile(
      process.env.APPWRITE_BUCKET_ID,
      ID.unique(),
      req.file.buffer,
      req.file.originalname
    );
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_USERS_COLLECTION_ID,
      user_id,
      { kyc_document_id: uploadedFile.$id },
      [
        `read("user:${user_id}")`,
        `write("user:${user_id}")`,
        `update("user:${user_id}")`,
        `delete("user:${user_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "KYC uploaded", file_id: uploadedFile.$id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Upload Delivery Proof
app.post("/upload-delivery-proof", upload.single("proof_photo"), async (req, res) => {
  const { request_id } = req.body;
  if (!request_id || !req.file) {
    return res.status(400).json({ error: "Missing request_id or proof_photo" });
  }
  try {
    const request = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id
    );
    const uploadedFile = await storage.createFile(
      process.env.APPWRITE_BUCKET_ID,
      ID.unique(),
      req.file.buffer,
      req.file.originalname
    );
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SHOPPING_REQUESTS_COLLECTION_ID,
      request_id,
      { proof_photo_id: uploadedFile.$id, status: "completed" },
      [
        `read("user:${request.shopper_id}")`,
        `write("user:${request.shopper_id}")`,
        `update("user:${request.shopper_id}")`,
        `delete("user:${request.shopper_id}")`,
        `read("user:${request.traveler_id}")`,
        `write("user:${request.traveler_id}")`,
        `update("user:${request.traveler_id}")`,
        `delete("user:${request.traveler_id}")`,
        `read("users")`,
      ]
    );
    res.status(200).json({ message: "Delivery proof uploaded", file_id: uploadedFile.$id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.get("/", (req, res) => {
  res.redirect("/api-docs");
});
app.listen(PORT, "0.0.0.0", () => console.log(`✅ Enhanced backend running on port ${PORT} on 0.0.0.0`));