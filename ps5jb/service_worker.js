const CACHE_NAME = 'offline-cache';

async function refresh_cache() {
    console.log('refreshing cache');

    // fetch the appcache file
    let appcache_filename = '/cache.appcache';

    let live_appcache = null;
    try {
        live_appcache = await fetch(appcache_filename);
    } catch (error) {
        // we're probably offline so just return
        return;
    }

    let live_appcache_clone = live_appcache.clone();

    const cache = await caches.open(CACHE_NAME);
    const cache_keys = await cache.keys();

    let cached_appcache = await cache.match(appcache_filename);

    let live_appcache_lines = (await live_appcache.text()).split('\n');

    // remove first entry (header)
    live_appcache_lines.shift();

    let cached_appcache_lines = [];

    if (cached_appcache) {
        cached_appcache_lines = (await cached_appcache.text()).split('\n');
        // remove first entry (header)     
        cached_appcache_lines.shift();
    }

    let cacheAllPayloads = await get_should_cache_payloads();

    // loop through all item in live appcache
    for (let i = 0; i < live_appcache_lines.length; i++) {
        let live_current_item = live_appcache_lines[i].split('#');

        let live_current_item_filename = live_current_item[0].trim();
        let live_current_item_hash = live_current_item[1].trim();

        let cache_key = self.location.origin + '/' +
            live_current_item_filename;

        if (live_current_item_filename.includes('payloads') && !cacheAllPayloads) {
            cache.delete(cache_key);
            continue;
        }

        // if not in cache key store, add it
        if (!cache_key_store_has_key(cache_keys, cache_key)) {
            cache.add(cache_key);
            console.log('new cache: ' + cache_key);
            continue;
        }

        //cache store contains item so check if hash is the same
        let cached_file_hash = get_file_hash_from_manifest_array_and_remove_from_array(
            cached_appcache_lines,
            live_current_item_filename
        );

        if (cached_file_hash == live_current_item_hash) {
            console.log('up-to-date cache: ' + cache_key);
            continue;
        }

        // hash is different or is new file so fetch and put in cache async
        cache.add(cache_key);
        console.log('updated cache: ' + cache_key);

    }

    // since we removed valid items from cached_appcache_lines, the remaining items are files that are no longer in the manifest so delete them from cache
    for (let i = 0; i < cached_appcache_lines.length; i++) {
        let cached_current_item = cached_appcache_lines[i].split('#');
        let cached_current_item_filename = cached_current_item[0].trim();
        cache.delete(cached_current_item_filename);
    }

    // store the new appcache in cache
    cache.put(appcache_filename, live_appcache_clone);

    console.log('finished refreshing cache');
}

function cache_key_store_has_key(cache_keys, key) {
    for (let i = 0; i < cache_keys.length; i++) {
        if (cache_keys[i].url == key) {
            return true;
        }
    }
    return false;
}

function get_file_hash_from_manifest_array_and_remove_from_array(manifest_lines_array, filename) {
    for (let i = 0; i < manifest_lines_array.length; i++) {
        let current_item = manifest_lines_array[i].split('#');
        let current_item_filename = current_item[0].trim();
        if (current_item_filename == filename) {
            let current_item_hash = current_item[1].trim();
            // remove current item from manifest array
            manifest_lines_array.splice(i, 1);
            return current_item_hash;
        }
    }
    return null;

}


// fetch a manifest file that contains all the files and hashes separated by hashtag and store this manifest file, and parse all the entries in it and precache them
self.addEventListener('install', event => {
    console.log('installing service worker');
    event.waitUntil(refresh_cache());
});

self.addEventListener('activate', event => {
    console.log('activating service worker');
    event.waitUntil(refresh_cache());
});

self.addEventListener('fetch', function (event) {
    console.log('fetching: ' + event.request);

    event.respondWith(
        fetch(event.request)
    );
    return; 

    console.log('fetching: ' + event.request);
    console.log('fetching url: ' + event.request.url);
    event.respondWith(async () => {
        let cache = await caches.open(CACHE_NAME);
        let response = await cache.match(event.request);
        if (response) {
            return response;
        }
        return (await fetch(event.request)).response;
    });

});


// sadly localstorage is inaccessable from service workers so we have to use indexeddb
function get_should_cache_payloads() {
    let dbName = 'ps5-exploit-host';
    let objectStoreName = 'settings';
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName);

        request.onerror = (event) => {
            reject(new Error("Error opening database: " + event.target.errorCode));
        };

        request.onupgradeneeded = (event) => {
            const db = event.target.result;

            if (!db.objectStoreNames.contains(objectStoreName)) {
                const objectStore = db.createObjectStore(objectStoreName, { keyPath: 'id', autoIncrement: true });
                objectStore.createIndex('value', 'value', { unique: false });
            }
        };

        request.onsuccess = (event) => {
            const db = event.target.result;

            const transaction = db.transaction(objectStoreName, 'readonly');
            const objectStore = transaction.objectStore(objectStoreName);

            const getRequest = objectStore.get('cache-all-payloads');

            getRequest.onsuccess = (event) => {
                const data = event.target.result;
                resolve(data);
                db.close();
            };

            getRequest.onerror = (event) => {
                reject(new Error("Error retrieving data: " + event.target.errorCode));
                db.close();
            };
        };
    });
}