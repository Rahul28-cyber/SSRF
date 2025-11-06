const express = require('express');
const path = require('path');
const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));

// Exact admin IP allowed to access admin resources
const ADMIN_IP = '192.168.1.209';

// Simulated product data per category
const products = {
  electronics: ['Smartphone', 'Laptop', 'Headphones'],
  books: ['Novel', 'Biography', 'Poetry'],
  // Vulnerable category with SSRF parameter input
  collectibles: ['Rare Coin', 'Vintage Stamp', 'Ancient Artifact'],
};

// Simulated user database for admin panel
const usersDb = {
  1: { username: "alice", deleted: false },
  2: { username: "bob", deleted: false },
  3: { username: "charlie", deleted: false },
};

const FLAG = "FLAG{ssrf_successful_user_deleted}";

// IP checker helper
function isAdminIP(req) {
  let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
  if (ip.includes('::ffff:')) ip = ip.split('::ffff:')[1];
  return ip === ADMIN_IP;
}

app.use(express.static('public'));

// Homepage - list categories
app.get('/', (req, res) => {
  const categories = Object.keys(products);
  let html = '<h1>Welcome to the Product Store!</h1><h2>Categories</h2><ul>';
  categories.forEach(cat => {
    html += `<li><a href="/category/${cat}">${cat}</a></li>`;
  });
  html += '</ul>';
  res.send(html);
});

// Category page
app.get('/category/:name', (req, res) => {
  const cat = req.params.name;
  if (!products[cat]) {
    return res.status(404).send("Category not found");
  }
  // If this is the vulnerable category, show SSRF input
  if (cat === 'collectibles') {
    let html = `<h1>${cat.charAt(0).toUpperCase() + cat.slice(1)}</h1><ul>`;
    products[cat].forEach(p => {
      html += `<li>${p}</li>`;
    });
    html += `</ul>
      <h3>Search for item details (enter URL):</h3>
      <form method="GET" action="/fetch">
      <input name="url" size="50" placeholder="Enter URL here" />
      <button type="submit">Fetch</button>
      </form>`;
    return res.send(html);
  }
  // Normal category page
  let html = `<h1>${cat.charAt(0).toUpperCase() + cat.slice(1)}</h1><ul>`;
  products[cat].forEach(p => {
    html += `<li>${p}</li>`;
  });
  html += '</ul>';
  res.send(html);
});

// SSRF vulnerable fetch endpoint triggered by form on collectibles page
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url parameter");

  // SSRF simulation - allow only some internal URLs
  if (url === 'http://internal/admin') {
    // Admin panel HTML showing users if called from SSRF (simulate admin IP internally)
    let html = `<h1>Admin Panel</h1><ul>`;
    Object.entries(usersDb).forEach(([id, user]) => {
      if (!user.deleted) {
        html += `<li>${user.username} 
          <form style="display:inline" method="POST" action="/delete_user">
          <input type="hidden" name="id" value="${id}" />
          <button type="submit">Delete User</button>
          </form></li>`;
      }
    });
    html += `</ul>`;
    return res.send(html);
  } else if (url.startsWith('http://internal/delete_user?id=')) {
    const userId = url.split('=').pop();
    if (!usersDb[userId] || usersDb[userId].deleted) {
      return res.send("User does not exist or already deleted.");
    }
    usersDb[userId].deleted = true;
    return res.send(`User deleted! <br> Flag: ${FLAG}`);
  }
  return res.status(403).send("Access denied or external URL blocked.");
});

// Admin page - only accessible exactly from admin IP
app.get('/admin', (req, res) => {
  if (!isAdminIP(req)) return res.status(403).send("Forbidden");

  let html = `<h1>Admin Panel</h1><ul>`;
  Object.entries(usersDb).forEach(([id, user]) => {
    if (!user.deleted) {
      html += `<li>${user.username} 
        <form style="display:inline" method="POST" action="/delete_user">
        <input type="hidden" name="id" value="${id}" />
        <button type="submit">Delete User</button>
        </form></li>`;
    }
  });
  html += `</ul>`;
  res.send(html);
});

// Delete user - only admin IP allowed (POST)
app.post('/delete_user', express.urlencoded({ extended: false }), (req, res) => {
  if (!isAdminIP(req)) return res.status(403).send("Forbidden");
  const id = req.body.id;
  if (!usersDb[id] || usersDb[id].deleted) return res.send("User not found");
  usersDb[id].deleted = true;
  res.send(`User deleted! <br> Flag: ${FLAG}`);
});

app.listen(port, () => {
  console.log(`Product Store SSRF CTF running at http://localhost:${port}`);
});
