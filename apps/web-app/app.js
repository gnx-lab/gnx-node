// PWA sin sesiones propias, credenciales ni APIs privilegiadas.
// Solo se registra en el origen HTTPS de la aplicación privada.
const isTrustedAppOrigin = window.location.protocol === 'https:' && window.location.hostname === 'app.gnx';
if (isTrustedAppOrigin && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('./sw.js', { scope: './' });
  });
}
