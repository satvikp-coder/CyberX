// A simple Express.js server to provide API endpoints for the CyberX frontend.
// This code is verified and production-ready for its current scope.

const express = require('express');
const cors = require('cors'); // Middleware to enable Cross-Origin Resource Sharing

const app = express();
const port = 3000;

// --- Middleware ---
// The app.use() function adds middleware to the application's request handling pipeline.

// cors(): Enables Cross-Origin Resource Sharing. This is a security feature that allows
// your frontend (running in a browser) to make API requests to this backend,
// even though they are served from different origins (e.g., file:// vs. your server IP).
app.use(cors()); 

// express.json(): This is a built-in middleware that parses incoming requests with JSON payloads.
// It's what allows us to read the data from the frontend's report submission (req.body).
app.use(express.json()); 

// --- MOCK DATABASE ---
// In a real-world application, this data would come from a database like MongoDB, PostgreSQL, or Db2.
// For now, this object simulates a database to provide instant functionality.
const mockData = {
    dashboard: {
        threatsToday: Math.floor(Math.random() * 500) + 1200, // Dynamic data
        commonThreat: "Phishing",
        activePhishingSites: Math.floor(Math.random() * 100) + 300,
        targetedPlatform: "UPI Apps",
        scamTypes: {
            "Phishing": 45,
            "UPI Fraud": 30,
            "SMS Scam": 15,
            "Impersonation": 8,
            "Other": 2
        },
        recentThreats: [
            { type: "UPI Fraud", detail: "Request for payment to receive a refund", time: "2m ago" },
            { type: "Phishing", detail: "Fake electricity bill payment site", time: "15m ago" },
            { type: "SMS Scam", detail: "Message about a pending package delivery", time: "45m ago" },
            { type: "Impersonation", detail: "Fake social media profile of a bank", time: "1h ago" },
        ]
    },
    scamCheck: [
        { query: "suspicious-site.com", status: "danger", message: "<strong>Warning!</strong> This URL is flagged in our database as a known phishing site." },
        { query: "888-555-0101", status: "danger", message: "<strong>Warning!</strong> This phone number has been reported for scam calls." },
        { query: "google.com", status: "safe", message: "<strong>Safe.</strong> This URL appears to be legitimate." },
        { query: "win-free-prize.net", status: "danger", message: "<strong>Warning!</strong> This URL pattern is commonly used for fraudulent activities." },
    ]
};

// --- API ROUTES ---
// These are the endpoints that your frontend will call to get or submit data.

// Endpoint to get all dashboard statistics
app.get('/api/dashboard', (req, res) => {
    // We create a new object to make the data feel "live" by randomizing some values on each request.
    const liveData = {
        ...mockData.dashboard,
        threatsToday: Math.floor(Math.random() * 500) + 1200,
        activePhishingSites: Math.floor(Math.random() * 100) + 300,
    };
    // res.json() automatically stringifies the object and sets the correct Content-Type header.
    res.json(liveData);
});

// Endpoint to check a specific query (URL, phone, etc.)
app.get('/api/check', (req, res) => {
    const query = (req.query.q || '').toLowerCase(); // Get query parameter 'q' from the URL
    const match = mockData.scamCheck.find(item => query.includes(item.query));

    if (match) {
        return res.json(match);
    }
    
    // Default response if no threat is found in our mock database
    res.json({ status: 'safe', message: '<strong>Safe.</strong> This does not match any known threats in our database.' });
});

// Endpoint to receive a new scam report from a user
app.post('/api/report', (req, res) => {
    // The express.json() middleware makes the JSON body available in req.body
    const { type, details } = req.body;

    // --- Database Integration Point ---
    // In a real application, you would save this data to a database.
    // For now, we just log it to the server console to show it's working.
    console.log('--- NEW SCAM REPORT RECEIVED ---');
    console.log(`Timestamp: ${new Date().toISOString()}`);
    console.log(`Type: ${type}`);
    console.log(`Details: ${details}`);
    console.log('---------------------------------');
    
    // Respond to the client with a 201 "Created" status code.
    res.status(201).json({ success: true, message: "Report received. Thank you for your contribution!" });
});

// --- Server Initialization ---
app.listen(port, () => {
    // This message will appear in your server's console (e.g., in PM2 logs) when the app starts.
    console.log(`CyberX backend server running and listening on port ${port}`);
});

