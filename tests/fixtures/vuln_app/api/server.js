const cors = require('cors')
app.use(cors({ origin: '*', credentials: true }))   // FAUTE : CORS * + credentials

app.get('/api/search', (req, res) => {
  const q = "SELECT * FROM items WHERE name = '" + req.query.name + "'"  // FAUTE : injection SQL
  db.query(q)
})
app.post('/debug/reset-db', (req, res) => { db.dropAll() })  // FAUTE : route de debug exposée

// FAUTE : SSRF — fetch d'une URL fournie par l'utilisateur
app.get('/api/fetch', (req, res) => { fetch(req.query.url).then(r => r.text()).then(t => res.send(t)) })

// FAUTE : webhook sans vérification de signature
app.post('/webhook/stripe', (req, res) => { processPayment(req.body) })

// FAUTE : login sans rate limiting + session par cookie sans CSRF
const session = require('express-session')
app.use(session({ secret: 's' }))
app.post('/login', (req, res) => { checkPassword(req.body.password) })
