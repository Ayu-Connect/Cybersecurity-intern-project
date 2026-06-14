const fs = require('fs');
const path = require('path');
const speakeasy = require('speakeasy');

const secretPath = path.join(__dirname, 'temp-secret.txt');
const totpPath = path.join(__dirname, 'temp-totp.txt');

console.log('2FA Watcher started. Monitoring temp-secret.txt...');

// Clean up old files
if (fs.existsSync(secretPath)) {
  try { fs.unlinkSync(secretPath); } catch (e) {}
}
if (fs.existsSync(totpPath)) {
  try { fs.unlinkSync(totpPath); } catch (e) {}
}

// Watch directory for changes
fs.watch(__dirname, (eventType, filename) => {
  if (filename === 'temp-secret.txt') {
    // Small delay to ensure writing is complete
    setTimeout(() => {
      try {
        if (fs.existsSync(secretPath)) {
          const secret = fs.readFileSync(secretPath, 'utf8').trim();
          if (secret && secret.length > 10) {
            const code = speakeasy.totp({
              secret: secret,
              encoding: 'base32'
            });
            console.log(`[Watcher] Secret detected: ${secret.substring(0, 5)}... -> Generated TOTP: ${code}`);
            fs.writeFileSync(totpPath, code, 'utf8');
          }
        }
      } catch (err) {
        console.error('[Watcher] Error generating TOTP:', err);
      }
    }, 100);
  }
});
