// PWA sin sesiones propias, secretos, pipes ni llamadas a localhost.
if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('./sw.js'));
