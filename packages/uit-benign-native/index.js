/**
 * uit-benign-native
 * Legitimate native addon wrapper demonstrating whitelisted lifecycle build hooks (Layer 1 FPR control).
 */

'use strict';

function computeChecksum(bufferInput) {
    const str = String(bufferInput || '');
    let sum = 0;
    for (let i = 0; i < str.length; i++) {
        sum = (sum + str.charCodeAt(i)) % 65535;
    }
    return sum;
}

module.exports = {
    computeChecksum
};
