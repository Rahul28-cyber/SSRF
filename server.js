// server.js - patched: sessioned SSRF challenge where ALL categories accept ?url=
// Drop this in place of your current server.js

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const port = 3000;

// --- CTF SETUP (keep similar to your original) ---
const ADMIN_IP_LAST_OCTET = 69;
const ADMIN_IP = `192.168.0.${ADMIN_IP_LAST_OCTET}`;
const ADMIN_PORT = 8080;
const ADMIN_URL_BASE = `http://${ADMIN_IP}:${ADMIN_PORT}`;

// Initial pristine users DB (never mutated)
// We will clone this into each session's usersDb
const initialUsersDb = {
  101: { username: "alice", deleted: false },
  102: { username: "bob", deleted: false },
  103: { username: "carlos", deleted: false }, // TARGET USER
  104: { username: "diana", deleted: false },
};

// Session store (in-memory). Each session holds its own usersDb, flag and solved state.
const sessions = {}; // sid -> { usersDb, flag, solved, createdAt }

// Session settings
const SESSION_TTL_MS = 20 * 60 * 1000; // 20 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // cleanup every 5 minutes

// Helpers
function makeFlag() {
  return `sp3ctr3CTF{${crypto.randomBytes(7).toString('hex')}}`;
}

function cloneUsersDb() {
  // deep clone initialUsersDb
  return JSON.parse(JSON.stringify(initialUsersDb));
}

function makeSession() {
  const sid = crypto.randomBytes(10).toString('hex');
  sessions[sid] = {
    usersDb: cloneUsersDb(),
    flag: makeFlag(),
    solved: false,
    createdAt: Date.now()
  };
  return sid;
}

function getOrCreateSession(req, res) {
  let sid = req.cookies && req.cookies.sid;
  if (!sid || !sessions[sid]) {
    sid = makeSession();
    // set cookie for session tracking, httpOnly
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', maxAge: SESSION_TTL_MS });
  }
  return sid;
}

// Cleanup job to free memory for expired sessions
setInterval(() => {
  const now = Date.now();
  for (const sid of Object.keys(sessions)) {
    if (now - sessions[sid].createdAt > SESSION_TTL_MS) {
      delete sessions[sid];
    }
  }
}, CLEANUP_INTERVAL_MS);

// --- EXPRESS SETUP ---
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'))); // serves home.html, styles.css etc.

// --- CORE SIMULATION FUNCTION (MIMICS INTERNAL SERVER) ---
// session-aware internal request simulator.
function simulateInternalRequestForSession(url, sid) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80');
    const path = urlObj.pathname;
    const searchParams = urlObj.searchParams;

    // Blocks external hosts (firewall simulation)
    if (!hostname.startsWith('192.168.0.') && hostname !== 'localhost' && hostname !== '127.0.0.1') {
      return { status: 403, body: `[FIREWALL BLOCK] Connection attempt to external server ${hostname} blocked. Only internal 192.168.0.x or localhost access is permitted.` };
    }

    // If this targets the admin server address/port we simulate the admin panel.
    if (hostname === ADMIN_IP && port == ADMIN_PORT) {
      // Ensure session exists
      const session = sessions[sid];
      if (!session) {
        return { status: 403, body: `[403 FORBIDDEN] Invalid or expired session.` };
      }

      // Serve /admin page
      if (path === '/admin') {
        const userList = Object.entries(session.usersDb)
          .filter(([id, u]) => !u.deleted)
          .map(([id, u]) => `- ${u.username} (Delete Link: ${ADMIN_URL_BASE}/admin/delete?username=${u.username})`)
          .join('\n');

        return {
          status: 200,
          body: `[200 OK] Internal Admin Interface:\n\nWelcome, System Admin.\n\n--- User Management ---\n${userList}\n\n[HINT] The target user is 'carlos'. Use the deletion link path to generate the final payload.`
        };
      }

      // The delete route: operate on the session DB and issue the session flag
      if (path === '/admin/delete') {
        const username = searchParams.get('username');

        if (username === 'carlos') {
          // find user inside session usersDb
          const userId = Object.keys(session.usersDb).find(id => session.usersDb[id].username === 'carlos');
          if (userId && !session.usersDb[userId].deleted) {
            // mark deleted inside this session only
            session.usersDb[userId].deleted = true;
            // mark solved and return the session flag (idempotent for this session)
            if (!session.solved) {
              session.solved = true;
              return { status: 200, body: `[200 SUCCESS] User '${username}' deleted by internal request.\n\nChallenge Solved!\n\nFlag: ${session.flag}` };
            } else {
              return { status: 200, body: `[200 OK] User '${username}' already deleted for this session. Flag already issued.` };
            }
          }
          return { status: 400, body: `Deletion failed. User '${username}' not found or already deleted in this session.` };
        }

        return { status: 400, body: `Deletion failed. User '${username}' is not the target.` };
      }

      // Unknown admin path
      return { status: 404, body: `[404 NOT FOUND] Path ${path} does not exist on the Admin Interface.` };
    }

    // scanning feedback for correct port but wrong IP in internal range
    if (hostname.startsWith('192.168.0.') && port == ADMIN_PORT) {
      return { status: 403, body: `[403 FORBIDDEN] Connection refused by ${hostname}:${port}. Target not found.` };
    }

    // stock check route (benign)
    if (path.startsWith('/stock/')) {
      return { status: 200, body: `[200 OK] Stock check for ID ${path.split('/').pop()} completed successfully. Stock level: 85. (Hostname: ${hostname})` };
    }

    // default: forbidden / not found
    return { status: 403, body: `[403 FORBIDDEN] Connection Refused or Service Not Found at ${hostname}:${port}.` };

  } catch (e) {
    console.error("URL Parsing Error:", e);
    return { status: 400, body: `[ERROR] Invalid URL format submitted: ${e.message}` };
  }
}

// small wrapper
const fetchVulnerableResourceForSession = (url, sid) => {
  if (!url) {
    return { status: 200, body: "[STATUS] Ready. Pass a 'url' parameter to fetch item details." };
  }
  return simulateInternalRequestForSession(url, sid);
};

// --- ROUTES ---
// Homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Category page - create/get session, then run vulnerable simulation using session state
// NOTE: Now every category is vulnerable to ?url= (not just 'collectibles')
app.get('/category/:name', (req, res) => {
  const category = req.params.name;
  const itemUrl = req.query.url; // This is the vulnerable parameter (applies to all categories)

  // Ensure session (cookie) for the visitor
  const sid = getOrCreateSession(req, res);

  // Category-specific default URLs (if no url param is provided)
  const defaultUrls = {
    collectibles: 'http://localhost:8080/stock/404-CTF-CO',
    electronics: 'http://localhost:8080/stock/404-CTF-EL',
    books: 'http://localhost:8080/stock/404-CTF-BK',
    apparel: 'http://localhost:8080/stock/404-CTF-AP',
    // fallback default
    default: 'http://localhost:8080/stock/404-CTF-A'
  };
  const defaultUrl = defaultUrls[category] || defaultUrls.default;

  let result = { status: 200, body: `[STATUS] View the source code to find where item details are fetched. Try appending '?url=.' to the address bar.` };

  // Apply vulnerable fetch to ALL categories
  result = fetchVulnerableResourceForSession(itemUrl || defaultUrl, sid);

  // render response
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
            <a href="/category/books" class="mx-3 hover:text-blue-200 transition duration-150">Books</a>
            <a href="/category/apparel" class="mx-3 hover:text-blue-200 transition duration-150">Apparel</a>
          </div>
        </nav>
      </header>

      <div class="main max-w-5xl mx-auto p-4 md:p-8">
        <h1 class="text-4xl font-extrabold text-gray-900 text-center mb-10">${category.charAt(0).toUpperCase() + category.slice(1)}</h1>

        <div class="bg-white p-6 rounded-xl shadow-lg mb-10 border-t-4 border-blue-500">
          <h2 class="text-2xl font-bold mb-4 text-blue-700">Item Details & Stock Check</h2>

          <div class="product-grid mb-6">
            <div class="card bg-gray-50 p-4">Item A</div>
            <div class="card bg-gray-50 p-4">Item B</div>
            <div class="card bg-gray-50 p-4">Item C</div>
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

// Redundant fetch route kept for compatibility (session-aware)
app.get('/fetch', (req, res) => {
  const sid = getOrCreateSession(req, res);
  const url = req.query.url;
  const result = fetchVulnerableResourceForSession(url, sid);
  res.status(result.status).send(result.body);
});

// Start
app.listen(port, () => {
  console.log(`\n======================================================`);
  console.log(`[CTF] SSRF Challenge (sessioned) is running at http://localhost:${port}`);
  console.log(`[CTF] The secret Admin IP is: ${ADMIN_IP}`);
  console.log(`Sessions expire after ${Math.round(SESSION_TTL_MS / 60000)} minutes.`);
  console.log(`======================================================\n`);
});
