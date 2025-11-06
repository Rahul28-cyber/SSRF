const express = require('express');
const path = require('path');
const app = express();
const port = 3000;
const fetch = require('node-fetch'); // Assuming node-fetch is available for simulated internal request

// --- CTF SETUP ---
// Randomly select a secret internal IP address for the admin panel
// const ADMIN_IP_LAST_OCTET = Math.floor(Math.random() * 254) + 1; // 1 to 255
const ADMIN_IP_LAST_OCTET = 69;
const ADMIN_IP = `192.168.0.${ADMIN_IP_LAST_OCTET}`;
const ADMIN_PORT = 8080;
const ADMIN_URL_BASE = `http://${ADMIN_IP}:${ADMIN_PORT}`;

// Simulated user database for the admin panel (Target is 'carlos')
const usersDb = {
    101: { username: "alice", deleted: false },
    102: { username: "bob", deleted: false },
    103: { username: "carlos", deleted: false }, // TARGET USER
    104: { username: "diana", deleted: false },
};

const FLAG = "sp3ctr3CTF{55RF_345Y_M0D3_1NT3RN4L_5C4N_C0MPL3T3}";

// --- EXPRESS SETUP ---
app.use(express.urlencoded({ extended: true }));

// IMPORTANT FIX: Use express.static to serve files from the 'public' directory
// The client will access files relative to this folder (e.g., /styles.css)
app.use(express.static(path.join(__dirname, 'public'))); 
// We can remove the dedicated 'styles.css' route now since it's in public.

// --- CORE SIMULATION FUNCTION (MIMICS INTERNAL SERVER) ---

// In a real environment, this function would make a genuine HTTP request.
// Here, we simulate the routing logic of the internal network based on the parsed URL.
function simulateInternalRequest(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80');
        const path = urlObj.pathname;
        const searchParams = urlObj.searchParams;

        // 1. Check for external/blocked IPs (Firewall simulation)
        if (!hostname.startsWith('192.168.0.') && hostname !== 'localhost' && hostname !== '127.0.0.1') {
            return { status: 403, body: `[FIREWALL BLOCK] Connection attempt to external server ${hostname} blocked. Only internal 192.168.0.x or localhost access is permitted.` };
        }

        // 2. Routing to the internal server (192.168.0.X:8080)
        if (hostname === ADMIN_IP && port == ADMIN_PORT) {
            
            // --- ADMIN PANEL ROUTES ---
            if (path === '/admin') {
                let userList = Object.entries(usersDb)
                    .filter(([id, u]) => !u.deleted)
                    .map(([id, u]) => `- ${u.username} (Delete Link: ${ADMIN_URL_BASE}/admin/delete?username=${u.username})`)
                    .join('\n');

                return { 
                    status: 200, 
                    body: `[200 OK] Internal Admin Interface:\n\nWelcome, System Admin.\n\n--- User Management ---\n${userList}\n\n[HINT] The target user is 'carlos'. Use the deletion link path to generate the final payload.` 
                };
            }
            
            // 3. Final Exploit Route (DELETE user 'carlos')
            if (path === '/admin/delete') {
                const username = searchParams.get('username');

                if (username === 'carlos') {
                    const userId = Object.keys(usersDb).find(id => usersDb[id].username === 'carlos');
                    if (userId && !usersDb[userId].deleted) {
                        usersDb[userId].deleted = true; // State change
                        return { status: 200, body: `[200 SUCCESS] User '${username}' deleted by internal request.\n\nChallenge Solved!\n\nFlag: ${FLAG}` };
                    }
                    return { status: 200, body: `User 'carlos' already deleted.` };
                }

                return { status: 400, body: `Deletion failed. User '${username}' not found or not the target.` };
            }

            // 4. Handle other paths on the admin server
            return { status: 404, body: `[404 NOT FOUND] Path ${path} does not exist on the Admin Interface.` };
            
        } else if (hostname.startsWith('192.168.0.') && port == ADMIN_PORT) {
            // Correct port, but wrong IP in the internal range (scanning feedback)
            return { status: 403, body: `[403 FORBIDDEN] Connection refused by ${hostname}:${port}. Target not found.` };
        }
        
        // 5. Default internal route (The benign stock check)
        if (path.startsWith('/stock/')) {
            return { status: 200, body: `[200 OK] Stock check for ID ${path.split('/').pop()} completed successfully. Stock level: 85. (Hostname: ${hostname})` };
        }

        // 6. Any other internal IP/path
        return { status: 403, body: `[403 FORBIDDEN] Connection Refused or Service Not Found at ${hostname}:${port}.` };


    } catch (e) {
        console.error("URL Parsing Error:", e);
        return { status: 400, body: `[ERROR] Invalid URL format submitted: ${e.message}` };
    }
}

// --- VULNERABLE ENDPOINT (Used by the categories page now) ---
// This is the /fetch route logic, but we will apply it directly in the /category/collectibles route for subtlety.
const fetchVulnerableResource = (url) => {
    if (!url) {
        return { status: 200, body: "[STATUS] Ready. Pass a 'url' parameter to fetch item details." };
    }
    return simulateInternalRequest(url);
};

// --- ROUTES ---

// Homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Category page (Now includes the main vulnerability presentation)
app.get('/category/:name', (req, res) => {
    const category = req.params.name;
    const itemUrl = req.query.url; // This is the vulnerable parameter!

    // Default stock URL for initial page load
    const defaultUrl = 'http://localhost:8080/stock/404-CTF-A';
    
    let result = { status: 200, body: `[STATUS] View the source code to find where item details are fetched. Try appending '?url=...' to the address bar.` };
    
    // Only run the vulnerable feature if the 'url' parameter is provided AND it's the right category
    if (category === 'collectibles') {
        result = fetchVulnerableResource(itemUrl || defaultUrl);
    } 

    // Inject the result into the page template
    const responseBody = result.body.replace(/\n/g, '<br>');
    const responseStatus = result.status;

    const htmlContent = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Category - ${category.toUpperCase()} | CTF</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="/styles.css">
            <style>
                .ssrf-response { background-color: #1f2937; color: #10b981; min-height: 200px; font-family: monospace; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; white-space: pre-wrap;}
                .response-error { color: #ef4444; }
                .response-success { color: #10b981; }
                .response-flag { color: #f59e0b; font-weight: bold; }
            </style>
        </head>
        <body class="bg-gray-100 font-sans">
            <header class="bg-blue-800 p-4 text-white shadow-md">
                <nav class="max-w-7xl mx-auto flex justify-between items-center">
                    <a href="/" class="text-2xl font-bold hover:text-blue-200 transition duration-150">CTF Shop</a>
                    <div>
                        <a href="/" class="mx-3 hover:text-blue-200 transition duration-150">Home</a>
                        <a href="/category/electronics" class="mx-3 hover:text-blue-200 transition duration-150">Electronics</a>
                        <a href="/category/collectibles" class="mx-3 hover:text-blue-200 transition duration-150">Collectibles</a>
                    </div>
                </nav>
            </header>

            <div class="main max-w-5xl mx-auto p-4 md:p-8">
                <h1 class="text-4xl font-extrabold text-gray-900 text-center mb-10">${category.charAt(0).toUpperCase() + category.slice(1)}</h1>
                
                <div class="bg-white p-6 rounded-xl shadow-lg mb-10 border-t-4 border-blue-500">
                    <h2 class="text-2xl font-bold mb-4 text-blue-700">Item Details & Stock Check</h2>
                    
                    <div class="product-grid mb-6">
                        <div class="card bg-gray-50 p-4">Rare Coin</div>
                        <div class="card bg-gray-50 p-4">Vintage Stamp</div>
                        <div class="card bg-gray-50 p-4">Ancient Artifact</div>
                    </div>
                    
                    <p class="text-sm text-gray-500 italic mb-4">
                        To maintain efficiency, item details are fetched from an internal service.
                        Current details are fetched from: <code class="bg-gray-200 p-1 rounded text-xs">${itemUrl || defaultUrl}</code>
                    </p>

                    <h3 class="text-xl font-semibold mt-6 mb-2">Internal Service Response (Status: ${responseStatus})</h3>
                    <pre class="ssrf-response text-sm ${responseBody.includes('ERROR') || responseBody.includes('FORBIDDEN') ? 'response-error' : (responseBody.includes('SUCCESS') || responseBody.includes('FLAG') ? 'response-flag' : 'response-success')}">${responseBody}</pre>

                </div>

                <a href="/" class="inline-block bg-gray-600 hover:bg-gray-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-150">
                    ← Back to Categories
                </a>
            </div>
        </body>
        </html>
    `;

    res.send(htmlContent);
});

// This route is now redundant but kept to prevent 404 if someone finds it, 
// though the vulnerability is meant to be in /category/collectibles.
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    const result = fetchVulnerableResource(url);
    res.status(result.status).send(result.body);
});


// --- LISTEN ---
app.listen(port, () => {
    console.log(`\n======================================================`);
    console.log(`[CTF] SSRF Challenge is running at http://localhost:${port}`);
    console.log(`[CTF] The secret Admin IP is: ${ADMIN_IP}`);
    console.log(`======================================================\n`);
});