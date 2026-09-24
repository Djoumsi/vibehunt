const cors = require('cors')
app.use(cors({ origin: '*', credentials: true }))   // FAUTE : CORS * + credentials

app.get('/api/search', (req, res) => {
  const q = "SELECT * FROM items WHERE name = '" + req.query.name + "'"  // FAUTE : injection SQL
  db.query(q)
})
app.post('/debug/reset-db', (req, res) => { db.dropAll() })  // FAUTE : route de debug exposée
