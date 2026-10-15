/**
 * uit-benign: Clean library module for baseline testing.
 * Implements standard utility functions without malicious hooks or obfuscation.
 */

function add(a, b) {
    return a + b;
}

function greet(name) {
    return `Hello, ${name}! Welcome to UIT Supply Chain Lab.`;
}

module.exports = {
    add,
    greet
};
