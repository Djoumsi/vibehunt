import { useEffect } from 'react'
export default function AdminPanel({ user }) {
  useEffect(() => {
    // FAUTE : contrôle admin uniquement côté client
    if (user.role !== 'admin') { window.location.href = '/' }
  }, [user])
  return <div>Panneau admin secret</div>
}
