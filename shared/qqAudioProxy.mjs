// shared/qqAudioProxy.mjs
// QQ 音乐音频代理：Folia 侧的 serverless 层，Vercel（api-ts/qq.ts）与
// Cloudflare（worker/qq.ts）两个入口共用。
//
// 背景：后端向 QQ 要到的 vkey 播放链接疑似绑定了请求它的 IP（即后端服务器的 IP），
// 手机用自己的 IP 去 QQ CDN 取音频会被拒，播放器报 MEDIA_ELEMENT_ERROR 格式错误。
// 所以播放链接不再直接发给手机：getMusicPlay 回包里的链接先改写成指向本后端的代理地址，
// 音频字节由后端自己去 CDN 取回来再流式转发给手机，vkey 请求与音频请求同源同 IP。
//
// 为什么代理地址里不直接带会话：播放器是普通的 <audio src>，发不出 X-QQ-Session
// 这个自定义头；会话放进 URL（`?cookie=`）又会把一个长期有效的凭证写进访问日志，
// 与「凭证永不进日志」冲突。所以改写时把播放链接封进一个一次性凭证里：
// AES-256-GCM 密封的 { url, mid, quality, exp }，单首歌、30 分钟有效；
// 代理端点只认这个密封凭证，不认会话，也不接受 mid/quality 现取（没有会话就取不到链接）。
// 密封密钥由 QQ_SESSION_SECRET 派生，无 secret 时不改写（本来也拿不到链接）。
//
// 安全：播放链接（含 vkey）、密封凭证、secret 永不进日志；日志只记 mid、quality 与状态码。
// 纯 Web API（fetch/Request/Response/WebCrypto），Edge 能收；不要拉 npm 包或 node:* 进来，
// 闭包 gate 在 test/unit/onlineMusic/qqServerlessClosure.test.ts。

import { logger } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/util/logger.js';

export const AUDIO_PROXY_PATH = '/audio';

// 密封凭证的有效期：一首歌 3–5 分钟，预取会提前拿链接（预取缓存 20 分钟），
// 30 分钟够覆盖；vkey 链接本身也有时效，凭证过期后播放器按原有重试逻辑重新要链接即可。
export const AUDIO_PROXY_TOKEN_TTL_MS = 30 * 60_000;

const jsonResponse = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
});

// 与上游 serverless/index.js 的 NO_SECRET 同文：无 secret 时代理路由一律 501。
export const NO_SECRET_MESSAGE = 'QQ_SESSION_SECRET is not set. Set it to enable login.';

const base64UrlEncode = (bytes) => {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
};

const base64UrlDecode = (text) => {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
    const normalized = text.replaceAll('-', '+').replaceAll('_', '/');
    let binary;
    try {
        binary = atob(normalized);
    } catch {
        return null;
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
};

/** 密封密钥与会话密钥分开派生：代理凭证泄露也不能反推会话。 */
const audioProxyKey = async (secret) => {
    const material = await globalThis.crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(`folia-qq-audio-proxy-v1:${secret}`),
    );
    return globalThis.crypto.subtle.importKey('raw', material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
};

/**
 * 把一条播放链接封进密封凭证（base64url 的 IV + 密文）。
 * 凭证里只有这一首歌的链接与过期时间，没有会话、没有 secret。
 */
export async function sealAudioPlayUrl(secret, { url, mid, quality }) {
    const key = await audioProxyKey(secret);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const payload = JSON.stringify({
        u: url,
        m: mid,
        q: quality,
        exp: Date.now() + AUDIO_PROXY_TOKEN_TTL_MS,
    });
    const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(payload),
    );
    const sealed = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    sealed.set(iv, 0);
    sealed.set(new Uint8Array(ciphertext), iv.byteLength);
    return base64UrlEncode(sealed);
}

/**
 * 解开密封凭证：形状不对、解不开、过期都回 null（调用方按 400/410 处理），
 * 绝不把凭证或链接写进日志，也不把解密失败的原因带出去。
 */
export async function unsealAudioPlayUrl(secret, token) {
    const sealed = base64UrlDecode(token);
    if (!sealed || sealed.byteLength <= 12) return null;
    let payload;
    try {
        const key = await audioProxyKey(secret);
        const plaintext = await globalThis.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: sealed.subarray(0, 12) },
            key,
            sealed.subarray(12),
        );
        payload = JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
        return null;
    }
    if (!payload || typeof payload !== 'object') return null;
    if (typeof payload.u !== 'string' || !payload.u || !/^https?:\/\//.test(payload.u)) return null;
    // 只放行 QQ 的音频 CDN 主机（与库内 streamCdnSelector 用的后缀规则一致）：
    // 凭证一旦被伪造也不至于把本端点当成任意地址的开放代理。
    let host = '';
    try {
        host = new URL(payload.u).hostname.toLowerCase();
    } catch {
        return null;
    }
    if (!host.endsWith('.qqmusic.qq.com') && !host.endsWith('.tc.qq.com')) return null;
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return null;
    return {
        url: payload.u,
        mid: typeof payload.m === 'string' ? payload.m : '',
        quality: typeof payload.q === 'string' ? payload.q : '',
        exp: payload.exp,
    };
}

/**
 * 两个 serverless 入口的音频代理路由分发：是 /audio 路径时返回 Response，
 * 不是时返回 null（调用方继续走 phone 路由与上游 handleRequest，body 不会被读掉）。
 * 只认 GET（播放器只会这样取音频）；无 secret 回 501（与库内 needsSecret 路由一致）。
 */
export async function routeAudioProxy(request, env = {}) {
    const url = new URL(request.url);
    if (url.pathname !== AUDIO_PROXY_PATH) return null;
    try {
        if (request.method !== 'GET') {
            return jsonResponse({ code: 405, message: 'GET required' }, 405, { Allow: 'GET' });
        }
        if (!env.QQ_SESSION_SECRET) {
            return jsonResponse({ code: 501, message: NO_SECRET_MESSAGE }, 501);
        }
        const payload = await unsealAudioPlayUrl(env.QQ_SESSION_SECRET, url.searchParams.get('t') ?? '');
        if (!payload) {
            logger.warn('qq-audio-proxy.bad-token', {});
            return jsonResponse({ code: 400, message: 'Invalid audio token' }, 400);
        }
        if (payload.exp <= Date.now()) {
            logger.warn('qq-audio-proxy.expired-token', { mid: payload.mid });
            return jsonResponse({ code: 410, message: 'Audio token expired' }, 410);
        }
        const headers = { Referer: 'https://y.qq.com' };
        const range = request.headers.get('range');
        if (range) headers.Range = range;
        const userAgent = request.headers.get('user-agent');
        if (userAgent) headers['User-Agent'] = userAgent;
        let upstream;
        try {
            upstream = await fetch(payload.url, { headers });
        } catch (error) {
            logger.warn('qq-audio-proxy.upstream-error', {
                mid: payload.mid,
                quality: payload.quality,
                name: error instanceof Error ? error.name : 'Error',
            });
            return jsonResponse({ code: 502, message: 'Upstream audio fetch failed' }, 502);
        }
        if (!upstream.ok) {
            logger.warn('qq-audio-proxy.upstream-refused', {
                mid: payload.mid,
                quality: payload.quality,
                status: upstream.status,
            });
            try {
                await upstream.body?.cancel();
            } catch {
                // 拒掉的响应体读不读都无所谓；取消失败不影响回包。
            }
            return new Response(null, { status: upstream.status });
        }
        const passthrough = new Headers();
        for (const name of ['content-type', 'content-length', 'content-range', 'accept-ranges']) {
            const value = upstream.headers.get(name);
            if (value) passthrough.set(name, value);
        }
        passthrough.set('cache-control', 'no-store');
        logger.info('qq-audio-proxy.served', {
            mid: payload.mid,
            quality: payload.quality,
            status: upstream.status,
        });
        // 响应体直接透传成流：整首歌不进内存（非流式响应有 4.5 MB 上限，放不下一首无损）。
        return new Response(upstream.body, { status: upstream.status, headers: passthrough });
    } catch (error) {
        // 未预期的错误不把内部细节带出去；日志里只记名字，不记链接与凭证。
        logger.warn('qq-audio-proxy.unexpected', { name: error instanceof Error ? error.name : 'Error' });
        return jsonResponse({ code: 500, message: 'Internal error' }, 500);
    }
}

/**
 * getMusicPlay 回包里的播放链接改写成代理地址（方案 A：前端不用动）。
 * 只改 data.playUrl 里有非空 url 的条目：空链接（含 restriction 诊断）原样保留，
 * 前端的「拿不到链接」诊断不受影响。无 secret、非 200、回包不是 JSON、
 * 或没有 playUrl 映射时原样返回——只重建 body，不改状态码与业务字段。
 *
 * `publicBase` 是调用方在公开侧的地址（例如 `https://host/api/qq`）：改写后
 * 的地址必须按公开路径拼——这里收到的 request 是去掉 `/api/qq` 前缀后的
 * 后端请求，只凭它是拼不出公开地址的。没给 publicBase 时不改写，
 * 宁可走直链也不发一条错地址的代理链接。
 */
export async function rewritePlayUrlsToProxy(response, request, env = {}, publicBase = '') {
    const url = new URL(request.url);
    if (request.method !== 'GET' || !url.pathname.startsWith('/getMusicPlay/')) return response;
    if (!env.QQ_SESSION_SECRET || response.status !== 200 || !publicBase) return response;
    let text;
    try {
        text = await response.text();
    } catch {
        return response;
    }
    const rebuild = (bodyText) => {
        const headers = {};
        response.headers.forEach((value, name) => {
            if (name !== 'content-type' && name !== 'content-length') headers[name] = value;
        });
        return new Response(bodyText, {
            status: response.status,
            headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
        });
    };
    let body;
    try {
        body = JSON.parse(text);
    } catch {
        return rebuild(text);
    }
    const playUrl = body?.data?.playUrl;
    if (!playUrl || typeof playUrl !== 'object') return rebuild(text);
    const quality = url.searchParams.get('quality') || '128';
    let changed = false;
    const next = { ...playUrl };
    for (const [mid, entry] of Object.entries(playUrl)) {
        const direct = entry && typeof entry === 'object' ? String(entry.url || '') : '';
        if (!direct) continue;
        const token = await sealAudioPlayUrl(env.QQ_SESSION_SECRET, { url: direct, mid, quality });
        next[mid] = { ...entry, url: `${publicBase}${AUDIO_PROXY_PATH}?t=${token}` };
        changed = true;
    }
    if (!changed) return rebuild(text);
    return rebuild(JSON.stringify({ ...body, data: { ...body.data, playUrl: next } }));
}
