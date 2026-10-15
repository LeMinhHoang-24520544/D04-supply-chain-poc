/**
 * uit-marker-lifecycle: Module demonstrating execution via package lifecycle script.
 * Main export is benign; the payload was executed in preinstall hook.
 */

function getMarkerStatus() {
    return {
        technique: "MITRE ATT&CK T1195.002 - Supply Chain Compromise",
        hook: "preinstall",
        safety: "Zero destructive payload. Only benign local telemetry written."
    };
}

module.exports = {
    getMarkerStatus
};
