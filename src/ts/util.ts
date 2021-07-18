import * as har from 'har-format';
import protocol = require('./protocol');
import thriftcodec = require('./thriftcodec');
import { ITomcatImport } from './types';

const hash = (bytes: string): string => {
    let h = 5381;

    for (let i = 0; i < bytes.length; i++) {
        h = ((h << 5) + h) + bytes.charCodeAt(i);
    }

    return String(h);
};

const hasMembers = (obj: object) => {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }

    if (Array.isArray(obj) && obj.length > 0) {
        return true;
    }

    for (const p in obj) {
        if (obj.hasOwnProperty(p)) {
            return true;
        }
    }

    return false;
};

const b64d = (s: string): string => {
    try {
        return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    } catch (e) {
        console.log(e);
        return '';
    }
};

const nameType = (val: any): string => {
    if (val === null) {
        return 'null';
    }
    if (Array.isArray(val)) {
        return 'array';
    }
    if (typeof val === 'number' && isNaN(val)) {
        return 'number (NaN)';
    }
    if (typeof val === 'number' && !isFinite(val)) {
        return 'number (Infinite)';
    }
    if (val instanceof RegExp) {
        return 'RegExp';
    }
    if (val instanceof Date) {
        return 'Date';
    }
    if (val instanceof Promise) {
        return 'Promise';
    }
    return typeof val;
};

const copyToClipboard = (text: string): void => {
    let cb = document.getElementById('clipboard') as HTMLInputElement;
    if (cb === null) {
        cb = document.createElement('input') as HTMLInputElement;
        cb.type = 'text';
        cb.id = 'clipboard';
        cb.style.position = 'relative';
        cb.style.left = '-10000px';
        document.body.appendChild(cb);
    }

    cb.value = typeof text === 'string' ? text : JSON.stringify(text);
    cb.select();
    document.execCommand('copy');
};

const tryb64 = (text: string): string => {
    if (typeof text === 'string' && /^([A-Za-z0-9/_+-]{4})+([A-Za-z0-9/_+=-]{1,4})?$/.test(text)) {
        return b64d(text);
    } else {
        return text;
    }
};

// Formats: https://github.com/snowplow/snowplow/wiki/Collector-logging-formats
const tomcat = [
    'timestamp', // date
    'timestamp', // time
    null, // x-edge-location
    null, // bytes sent
    'ipAddress',
    'method', // method
    'hostname', // remote host
    'path',
    null, // status code
    'refererUri',
    'userAgent',
    'querystring',
    null, // cookies
    null, // x-edge-result-type
    null, // x-edge-request-id
    'contentType',
    'body',
    null, // protocol
    null, // cs-bytes
    null, // time-taken
];

const thriftToRequest = (payload?: ITomcatImport): Partial<har.Entry> | undefined => {
    if (typeof payload !== 'object' ||
        payload === null ||
        (!payload.hasOwnProperty('querystring') && !payload.hasOwnProperty('body'))) {
        return;
    }

    const headers: har.Header[] = [];
    const cookies: har.Cookie[] = [{ name: 'sp', value: (payload.networkUserId as string)}];

    const pheaders = (payload.headers as {[header: string]: string});
    for (const p in pheaders) {
        if (payload.headers.hasOwnProperty(p) && pheaders[p] !== '-') {
            headers.push({name: p, value: pheaders[p]});
        }
    }

    const uri = [
        'https://',
        'badbucket.invalid',
        (payload.path || '/'),
        (payload.querystring ? '?' + payload.querystring : ''),
    ].join('');

    // mock out the rest of the Entry interface
    return {
        pageref: 'page_bad',
        request: {
            bodySize: 0,
            cookies,
            headers,
            headersSize: 0,
            httpVersion: 'HTTP/1.1',
            method: 'body' in payload ? 'POST' : 'GET',
            postData: {
                mimeType: 'application/json',
                params: [],
                text: tryb64(payload.body as string),
            },
            queryString: [],
            url: uri,
        },
        response: {
            bodySize: 0,
            content: {
                mimeType: 'text/html',
                size: 0,
                text: '',
            },
            cookies,
            headers: [],
            headersSize: 0,
            httpVersion: 'HTTP/1.1',
            redirectURL: '',
            status: 200,
            statusText: 'OK',
        },
        startedDateTime: JSON.stringify(new Date(payload.timestamp as string)),
    };
};

const esToRequests = (data: object[]): har.Entry[] => {
    return data.map((hit) => {
        if (hit.hasOwnProperty('collector_tstamp')) {
            return goodToRequests(hit as { [esKeyName: string]: string }) as har.Entry;
        } else {
            return badToRequests([JSON.stringify(hit)])[0];
        }
    });
};

const goodToRequests = (data: { [esKeyName: string]: string | object }): Partial<har.Entry> => {
    const uri = new URL('https://elasticsearch.invalid/i');
    const reverseTypeMap: { [event: string]: string } = {
        page_ping: 'Page Ping',
        page_view: 'Pageview',
        struct: 'Structured Event',
        transaction: 'Transaction',
        transaction_item: 'Transaction Item',
        unstruct: 'Self-Describing Event',
    };

    const contexts = [];

    for (const p in data) {
        if (data.hasOwnProperty(p) && data[p] !== null) {
            const key = (protocol.esMap as { [esKeyName: string]: string})[p];
            const val = data[p];
            if (key !== '') {
                if (key === 'e') {
                    uri.searchParams.set(key, reverseTypeMap[val as string]);
                } else if (/tstamp/.test(p)) {
                    const d = new Date(val as string);
                    uri.searchParams.set(key, (+d).toString(10));
                } else if (/^unstruct_event_/.test(p)) {
                    const { event_vendor, event_name, event_format, event_version} = data;

                    const wrapped = {
                        data: {
                            data: val,
                            schema: `iglu:${event_vendor}/${event_name}/${event_format}/${event_version}`,
                        },
                        schema: 'iglu:com.snowplowanalytics.snowplow/unstruct_event/jsonschema/1-0-0',
                    };

                    uri.searchParams.set('ue_pr', JSON.stringify(wrapped));
                } else if (/^contexts_/.test(p)) {
                    // the 'good' enrichment process irrecoverably destroys vendor/version info, so guess
                    const schemaname = p.replace('contexts_', '')
                                        .replace(/_(\d)+$/, '/jsonschema/$1-0-0')
                                        .replace(/(^.+)_([^_]+_[^_]+)/, '$1/$2')
                                        .replace(/_/g, '.')
                                        .replace(/\/([^\./]+).([^\./]+)/, '/$1_$2');

                    for (const c of data[p]) {
                        contexts.push({
                            data: c,
                            schema: 'iglu:' + schemaname,
                        });
                    }
                } else {
                    uri.searchParams.set(key, val as string);
                }
            }
        }
    }

    if (contexts.length) {
        const wrapped = {
            data: contexts,
            schema: 'iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0',
        };

        uri.searchParams.set('co', JSON.stringify(wrapped));
    }

    return {
        pageref: 'page_good',
        request: {
            bodySize: 0,
            cookies: [],
            headers: [],
            headersSize: 0,
            httpVersion: 'HTTP/1.1',
            method: 'GET',
            queryString: [],
            url: uri.href,
        },
        response: {
            bodySize: 0,
            content: {
                mimeType: 'text/html',
                size: 0,
                text: '',
            },
            cookies: [],
            headers: [],
            headersSize: 0,
            httpVersion: 'HTTP/1.1',
            redirectURL: '',
            status: 200,
            statusText: 'OK',
        },
        startedDateTime: new Date().toISOString(),
    };

};

const newBadRowToRequests = (data: ITomcatImport | undefined, schema: string): ITomcatImport | undefined => {
    // TODO: Currently handles data.payload.raw.
    console.log("New bad row payload - ", data);

    if (!data) return data;
    if (data.hasOwnProperty("querystring")) return data;

    const result: ITomcatImport = {};

    // Build the bad row
    result["schema"] = schema;
    result["encoding"] = data["encoding"];
    result["headers"] = data["headers"];
    result["hostname"] = data["hostname"];
    result["ipAddress"] = data["ipAddress"];
    result["networkUserId"] = data["userId"];
    result["timestamp"] = data["timestamp"];
    result["userAgent"] = data["useragent"];
    result["path"] = "bad_rows";
    
    let q = [];
    let params = data["parameters"];
    for (var p in params) {
        q.push(encodeURIComponent(params[p].name) + "=" + encodeURIComponent(params[p].value));
    }
    result["querystring"] = q.join("&");

    console.log("Bad row built - ", result);
    return result;
}

const badToRequests = (data: string[]): har.Entry[] => {
    const logs = data.map((row) => {
        if (!row.length) {
            return;
        }

        let js = null;

        try {
            js = JSON.parse(row);
        } catch {
            js = row;
        }

        if (typeof js == "object" && js !== null) {
            if (js.hasOwnProperty("line")) {
                // Older bad row format
                js = js.line;
            } else if (js.hasOwnProperty("schema") && js.hasOwnProperty("data")) {
                // Newer bad row format
                if (!/^iglu:com\.snowplowanalytics\.snowplow\.badrows/.test(js.schema)) {
                    console.log("Unrecognized bad row iglu schema", js);
                    return;
                }

                if (typeof js.data.payload == "string") {
                    js = js.data.payload;
                } else {
                    return newBadRowToRequests(js.data.payload.raw || js.data.payload || undefined, js.schema);
                }
            } else {
                console.log("Unrecognized bad row format. ", js);
                return;
            }
        }

        if (typeof js === 'string') {
            // Check for timestamp to identify Tomcat bad row logs
            if (/^[0-9 -]+\t/.test(js)) {
                const result: ITomcatImport  = { headers: { Referer: ''} };
                js.split('\t').forEach((x, i) => {
                    const field = tomcat[i];
                    switch (field) {
                    case 'timestamp':
                        // There are two timestamp fields, check if we've already processed one
                        if (result.hasOwnProperty(field) && typeof result[field] === 'string') {
                            const d = new Date();
                            let parts = null;

                            // Pretty sure we see date first, but check if they're swapped just in case
                            if (x.indexOf(':') > -1) {
                                parts = x.split(':').map((p: string) => parseInt(p, 10));
                                d.setHours(parts[0]);
                                d.setMinutes(parts[1]);
                                d.setSeconds(parts[2]);
                                // @ts-ignore we know this is a string from above
                                parts = result[field].split('-');
                                d.setFullYear(parts[0]);
                                d.setMonth(parts[1]);
                                d.setDate(parts[2]);
                            } else {
                                // @ts-ignore we know this is a string from above
                                parts = result[field].split(':');
                                d.setHours(parts[0]);
                                d.setMinutes(parts[1]);
                                d.setSeconds(parts[2]);
                                parts = x.split('-').map((p: string) => parseInt(p, 10));
                                d.setFullYear(parts[0]);
                                d.setMonth(parts[1]);
                                d.setDate(parts[2]);
                            }

                            result[field] = '' + (+d);
                        } else {
                            result[field] = x;
                        }
                        break;
                    case 'body':
                        if (x !== '-') {
                            result.body = tryb64(x);
                        }
                        break;
                    case 'querystring':
                        const qs = /cv=([^&]+).*nuid=([^&]+)/.exec(x);
                        if (qs) {
                            result.collector = qs[1];
                            result.networkUserId = qs[2];
                        }
                        result[field] = x;
                        break;
                    case 'userAgent':
                    case 'contentType':
                        result[field] = decodeURIComponent(x.replace(/\+/g, ' '));
                        break;
                    case 'refererUri':
                        result[field] = x;
                        if (typeof result.headers === 'object') {
                            result.headers.Referer = x;
                        }
                        break;
                    case null:
                        break;
                    default:
                        result[field] = x;
                    }
                });

                if (result.method === 'OPTIONS') {
                    return;
                } else {
                    return result;
                }
            // B64 encoded, hopefully thrift from mini/realtime
            } else if (/^([A-Za-z0-9/+]{4})+([A-Za-z0-9/+=]{4})?$/.test(js)) {
                try {
                    return thriftcodec.decodeB64Thrift(js, thriftcodec.schemas['collector-payload']) as ITomcatImport;
                } catch (e) {
                    console.log(e);
                }
            }
        }
    });

    const entries = [];

    for (const entry of logs.map(thriftToRequest)) {
        if (entry !== undefined) {
            entries.push(entry as har.Entry);
        }
    }

    return entries;
};

export = {badToRequests, b64d, esToRequests, hash, hasMembers, nameType, copyToClipboard, thriftToRequest, tryb64};
