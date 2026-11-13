/**
 * Sample JavaScript source file for SecureBuild upload testing.
 * This module contains no real secrets or credentials.
 */

"use strict";

/**
 * Format a severity level to a display label.
 * @param {string} severity
 * @returns {string}
 */
function formatSeverity(severity) {
    const levels = {
        CRITICAL: "🔴 Critical",
        HIGH:     "🟠 High",
        MEDIUM:   "🟡 Medium",
        LOW:      "🟢 Low",
        INFO:     "⚪ Info",
    };
    return levels[severity?.toUpperCase()] || severity || "Unknown";
}

/**
 * Calculate total vulnerability count from a counts object.
 * @param {{ critical: number, high: number, medium: number, low: number }} counts
 * @returns {number}
 */
function totalVulns(counts) {
    if (!counts) return 0;
    return (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0) + (counts.low || 0);
}

module.exports = { formatSeverity, totalVulns };
