/**
 * uit-core-auth (PoC Dependency Confusion + Obfuscation)
 * Safe demonstration of evasion using Base64 encoded payload decoded at runtime.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');

// Safe payload string:
// "console.log('[D04 AUDIT MARKER] Dependency Confusion triggered: uit-core-auth v99.9.9 active');"
const encodedPayload = "Y29uc29sZS5sb2coJ1tEMDQgQVVESVQgTUFSS0VSXSBEZXBlbmRlbmN5IENvbmZ1c2lvbiB0cmlnZ2VyZWQ6IHVpdC1jb3JlLWF1dGggdjk5LjkuOSBhY3RpdmUnKTs=";

// Obfuscated dynamic execution simulation (Triggers Layer 2 Detection)
eval(Buffer.from(encodedPayload, 'base64').toString('utf-8'));

// Benign marker file creation
const markerDir = os.platform() === 'win32' ? 'C:\\Users\\Public' : '/tmp';
const markerFile = path.join(markerDir, 'uit_marker_dependency_confusion.log');
try {
    fs.writeFileSync(markerFile, `[DEPENDENCY CONFUSION MARKER] Loaded version 99.9.9 at ${new Date().toISOString()}\n`);
} catch (e) {
    // Silent fail if directory permission restricted
}

module.exports = {
    authenticate: function(user, pass) {
        console.log(`[AUTH-STUB] Authenticating ${user}`);
        return true;
    }
};
