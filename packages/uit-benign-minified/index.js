/**
 * uit-benign-minified
 * Clean entry module exporting UI icon helper and bundled utilities.
 */

'use strict';

const bundle = require('./dist/bundle.min.js');

module.exports = {
    getBadgeIcon: bundle.getBadgeIcon,
    formatLabel: bundle.formatLabel
};
