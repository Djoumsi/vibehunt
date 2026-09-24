// OK : la clé secrète reste côté serveur
export default async function handler(req, res) {
  const key = process.env.OPENAI_API_KEY
  // ... appel serveur
  res.json({ ok: true })
}
