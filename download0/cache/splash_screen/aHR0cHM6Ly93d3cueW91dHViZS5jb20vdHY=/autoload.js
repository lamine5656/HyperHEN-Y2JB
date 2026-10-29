window.AUTOLOAD_PROMISE = (async function () {
    await load_localscript('Relapse.js');
    await window.RELAPSE_PROMISE;
})();
