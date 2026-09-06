const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// In-memory storage (in production, use a database)
const users = {
  'saqibsarwar@cc.cc': {
    password: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', // Biscoe@@3
    role: 'admin'
  }
};

const apiKeys = new Map();
const keyUsage = new Map();

// Admin credentials
const ADMIN_EMAIL = 'saqibsarwar@cc.cc';
const JWT_SECRET = process.env.JWT_SECRET || 'sakuda-secret-key-change-in-production';

// Proxy API
const PROXY_API_BASE = 'https://apifb-ten.vercel.app/api';

function verifyApiKey(key) {
  const keyData = apiKeys.get(key);
  if (!keyData) return false;
  
  // Check if key is active
  if (!keyData.active) return false;
  
  // Check expiration
  if (keyData.expiresAt && Date.now() > keyData.expiresAt) {
    return false;
  }
  
  // Update usage
  keyUsage.set(key, (keyUsage.get(key) || 0) + 1);
  
  return true;
}

function generateApiKey(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Main handler
export default async function handler(req) {
  const { method } = req;
  const { pathname, searchParams } = new URL(req.url);
  
  // Admin dashboard
  if (pathname === '/admin' && method === 'GET') {
    return new Response(getAdminHTML(), {
      headers: { 'Content-Type': 'text/html' }
    });
  }
  
  // Login endpoint
  if (pathname === '/api/login' && method === 'POST') {
    try {
      const body = await req.json();
      const { email, password } = body;
      
      if (!email || !password) {
        return new Response(JSON.stringify({ error: 'Email and password required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const user = users[email];
      if (!user) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const token = jwt.sign(
        { email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return new Response(JSON.stringify({ token, user: { email, role: user.role } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Verify token endpoint
  if (pathname === '/api/verify' && method === 'GET') {
    const token = searchParams.get('token');
    if (!token) {
      return new Response(JSON.stringify({ valid: false }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      return new Response(JSON.stringify({ valid: true, user: decoded }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ valid: false }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Get all API keys (admin only)
  if (pathname === '/api/keys' && method === 'GET') {
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role !== 'admin') {
        return new Response(JSON.stringify({ error: 'Forbidden' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const keys = Array.from(apiKeys.entries()).map(([key, data]) => ({
        key: key.substring(0, 8) + '...', // Partial key for security
        fullKey: key,
        ...data,
        usage: keyUsage.get(key) || 0
      }));
      
      return new Response(JSON.stringify({ keys }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Create API key (admin only)
  if (pathname === '/api/keys' && method === 'PUT') {
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role !== 'admin') {
        return new Response(JSON.stringify({ error: 'Forbidden' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const body = await req.json();
      const { name, documentation, expiresIn } = body;
      
      if (!name) {
        return new Response(JSON.stringify({ error: 'Name is required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const key = generateApiKey();
      const expiresAt = expiresIn ? Date.now() + (expiresIn * 1000 * 60 * 60 * 24) : null;
      
      apiKeys.set(key, {
        name,
        documentation,
        active: true,
        createdAt: Date.now(),
        expiresAt,
        createdBy: decoded.email
      });
      
      return new Response(JSON.stringify({ 
        key,
        name,
        documentation,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Invalid token or request' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Delete API key (admin only)
  if (pathname.startsWith('/api/keys/') && (method === 'DELETE' || method === 'PUT')) {
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role !== 'admin') {
        return new Response(JSON.stringify({ error: 'Forbidden' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const keyToDelete = pathname.split('/').pop();
      if (apiKeys.has(keyToDelete)) {
        apiKeys.delete(keyToDelete);
        keyUsage.delete(keyToDelete);
        return new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      return new Response(JSON.stringify({ error: 'Key not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Proxy to existing API with key authentication
  if (method === 'GET') {
    const key = searchParams.get('key');
    if (!key || !verifyApiKey(key)) {
      return new Response(JSON.stringify({ error: 'Invalid or missing API key' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Remove key from params before proxying
    const newSearchParams = new URLSearchParams(searchParams);
    newSearchParams.delete('key');
    
    // Build proxy URL
    const proxyPath = pathname.replace('/api', '');
    const proxyUrl = `${PROXY_API_BASE}${proxyPath}${newSearchParams.toString() ? '?' + newSearchParams.toString() : ''}`;
    
    try {
      const response = await fetch(proxyUrl);
      const data = await response.json();
      
      return new Response(JSON.stringify(data), {
        status: response.status,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: 'Proxy error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  return new Response('Not Found', { status: 404 });
}

function getAdminHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sakuda API Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .glass {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body class="min-h-screen gradient-bg">
    <div id="app"></div>
    
    <script>
        const API_BASE = window.location.origin;
        let token = localStorage.getItem('sakuda_token');
        
        function render() {
            const app = document.getElementById('app');
            
            if (!token) {
                app.innerHTML = \`
                    <div class="min-h-screen flex items-center justify-center p-4">
                        <div class="glass rounded-2xl p-8 w-full max-w-md">
                            <h1 class="text-3xl font-bold text-white mb-2">Sakuda API</h1>
                            <p class="text-white/70 mb-8">Admin Dashboard</p>
                            
                            <form id="loginForm" class="space-y-4">
                                <div>
                                    <label class="block text-white/80 text-sm mb-2">Email</label>
                                    <input type="email" id="email" required
                                        class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/50"
                                        placeholder="saqibsarwar@cc.cc">
                                </div>
                                <div>
                                    <label class="block text-white/80 text-sm mb-2">Password</label>
                                    <input type="password" id="password" required
                                        class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/50"
                                        placeholder="••••••••">
                                </div>
                                <button type="submit"
                                    class="w-full py-3 bg-white text-purple-600 font-semibold rounded-lg hover:bg-white/90 transition">
                                    Login
                                </button>
                            </form>
                            <p id="error" class="text-red-300 mt-4 text-sm hidden"></p>
                        </div>
                    </div>
                \`;
                
                document.getElementById('loginForm').addEventListener('submit', handleLogin);
            } else {
                loadDashboard();
            }
        }
        
        async function handleLogin(e) {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const error = document.getElementById('error');
            
            try {
                const res = await fetch(\`\${API_BASE}/api/login\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await res.json();
                
                if (res.ok) {
                    token = data.token;
                    localStorage.setItem('sakuda_token', token);
                    render();
                } else {
                    error.textContent = data.error;
                    error.classList.remove('hidden');
                }
            } catch (err) {
                error.textContent = 'Login failed';
                error.classList.remove('hidden');
            }
        }
        
        async function loadDashboard() {
            const app = document.getElementById('app');
            app.innerHTML = \`
                <div class="min-h-screen p-8">
                    <div class="max-w-6xl mx-auto">
                        <div class="flex justify-between items-center mb-8">
                            <div>
                                <h1 class="text-3xl font-bold text-white">Sakuda API Admin</h1>
                                <p class="text-white/70">Manage API keys and access</p>
                            </div>
                            <button onclick="logout()" 
                                class="px-4 py-2 bg-white/10 text-white rounded-lg hover:bg-white/20 transition">
                                Logout
                            </button>
                        </div>
                        
                        <div class="glass rounded-2xl p-6 mb-6">
                            <h2 class="text-xl font-semibold text-white mb-4">Create New API Key</h2>
                            <form id="createKeyForm" class="space-y-4">
                                <div>
                                    <label class="block text-white/80 text-sm mb-2">Key Name</label>
                                    <input type="text" id="keyName" required
                                        class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/50"
                                        placeholder="e.g., Client A - Production">
                                </div>
                                <div>
                                    <label class="block text-white/80 text-sm mb-2">Documentation</label>
                                    <textarea id="keyDocs" rows="3"
                                        class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/50"
                                        placeholder="Describe what this key is for and who should use it"></textarea>
                                </div>
                                <div>
                                    <label class="block text-white/80 text-sm mb-2">Expires In (days, optional)</label>
                                    <input type="number" id="keyExpires"
                                        class="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-white/50"
                                        placeholder="Leave empty for permanent key">
                                </div>
                                <button type="submit"
                                    class="px-6 py-3 bg-white text-purple-600 font-semibold rounded-lg hover:bg-white/90 transition">
                                    Generate API Key
                                </button>
                            </form>
                        </div>
                        
                        <div class="glass rounded-2xl p-6">
                            <h2 class="text-xl font-semibold text-white mb-4">API Keys</h2>
                            <div id="keysList" class="space-y-3">
                                <p class="text-white/50">Loading...</p>
                            </div>
                        </div>
                    </div>
                </div>
            \`;
            
            document.getElementById('createKeyForm').addEventListener('submit', handleCreateKey);
            loadKeys();
        }
        
        async function loadKeys() {
            try {
                const res = await fetch(\`\${API_BASE}/api/keys\`, {
                    headers: { 'Authorization': \`Bearer \${token}\` }
                });
                
                if (res.ok) {
                    const data = await res.json();
                    const keysList = document.getElementById('keysList');
                    
                    if (data.keys.length === 0) {
                        keysList.innerHTML = '<p class="text-white/50">No API keys created yet</p>';
                        return;
                    }
                    
                    keysList.innerHTML = data.keys.map(key => \`
                        <div class="bg-white/5 rounded-lg p-4 border border-white/10">
                            <div class="flex justify-between items-start">
                                <div>
                                    <h3 class="font-semibold text-white">\${key.name}</h3>
                                    <p class="text-white/60 text-sm mt-1">\${key.documentation || 'No documentation'}</p>
                                    <div class="mt-2 flex items-center gap-4 text-sm">
                                        <span class="text-white/50">Usage: \${key.usage}</span>
                                        <span class="text-white/50">Created: \${new Date(key.createdAt).toLocaleDateString()}</span>
                                        \${key.expiresAt ? \`<span class="text-white/50">Expires: \${new Date(key.expiresAt).toLocaleDateString()}</span>\` : ''}
                                    </div>
                                </div>
                                <div class="flex items-center gap-2">
                                    <button onclick="copyKey('\${key.fullKey}')"
                                        class="px-3 py-1 bg-white/10 text-white text-sm rounded hover:bg-white/20 transition">
                                        Copy Key
                                    </button>
                                    <button onclick="deleteKey('\${key.fullKey}')"
                                        class="px-3 py-1 bg-red-500/20 text-red-300 text-sm rounded hover:bg-red-500/30 transition">
                                        Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    \`).join('');
                }
            } catch (err) {
                console.error('Failed to load keys:', err);
            }
        }
        
        async function handleCreateKey(e) {
            e.preventDefault();
            const name = document.getElementById('keyName').value;
            const documentation = document.getElementById('keyDocs').value;
            const expiresIn = document.getElementById('keyExpires').value;
            
            try {
                const res = await fetch(\`\${API_BASE}/api/keys\`, {
                    method: 'PUT',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${token}\`
                    },
                    body: JSON.stringify({ 
                        name, 
                        documentation,
                        expiresIn: expiresIn ? parseInt(expiresIn) : null
                    })
                });
                
                if (res.ok) {
                    document.getElementById('createKeyForm').reset();
                    loadKeys();
                    alert('API key created successfully!');
                } else {
                    const data = await res.json();
                    alert('Failed to create key: ' + data.error);
                }
            } catch (err) {
                alert('Failed to create key');
            }
        }
        
        async function deleteKey(key) {
            if (!confirm('Are you sure you want to delete this key?')) return;
            
            try {
                const res = await fetch(\`\${API_BASE}/api/keys/\${key}\`, {
                    method: 'DELETE',
                    headers: { 'Authorization': \`Bearer \${token}\` }
                });
                
                if (res.ok) {
                    loadKeys();
                } else {
                    alert('Failed to delete key');
                }
            } catch (err) {
                alert('Failed to delete key');
            }
        }
        
        function copyKey(key) {
            navigator.clipboard.writeText(key);
            alert('API key copied to clipboard!');
        }
        
        function logout() {
            localStorage.removeItem('sakuda_token');
            token = null;
            render();
        }
        
        render();
    </script>
</body>
</html>`;
}