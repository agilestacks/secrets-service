const hooks = require('hooks'); // eslint-disable-line import/no-unresolved, import/no-extraneous-dependencies

/* eslint no-param-reassign: ["error", { "props": false }] */

hooks.beforeEach((tx) => {
    if (tx.request.method === 'DELETE') tx.skip = true;
});
