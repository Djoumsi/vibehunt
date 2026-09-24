export default function Comment({ text }) {
  // FAUTE : XSS via dangerouslySetInnerHTML alimenté par une prop
  return <div dangerouslySetInnerHTML={{ __html: text }} />
}
