import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// test/unit/onlineMusic/qqAudioProxy.test.ts
// QQ 音频代理（shared/qqAudioProxy.mjs）：密封凭证只用 WebCrypto 验证，不发任何真实请求；
// 上游 CDN 用 vi.stubGlobal 替身。不断言任何真实播放链接，只断言改写、密封与转发的行为。

import {
    AUDIO_PROXY_PATH,
    AUDIO_PROXY_TOKEN_TTL_MS,
    rewritePlayUrlsToProxy,
    routeAudioProxy,
    sealAudioPlayUrl,
    unsealAudioPlayUrl,
} from '../../../shared/qqAudioProxy.mjs';

const SECRET = 'test-secret-for-audio-proxy';
const OTHER_SECRET = 'test-secret-for-someone-else';
const ENV = { QQ_SESSION_SECRET: SECRET };
const DIRECT_URL = 'https://ws.stream.qqmusic.qq.com/C400003abc.m4a?vkey=TESTVKEY&guid=1&uin=0&fromtag=0';

const audioRequest = (url: string, init?: RequestInit) => new Request(url, init);

const getMusicPlayResponse = (playUrl: Record<string, unknown>) => new Response(
    JSON.stringify({ code: 0, data: { playUrl } }),
    { status: 200, headers: { 'content-type': 'application/json' } },
);

describe('QQ audio proxy tokens', () => {
    it('seals a play URL and unseals it back with the same mid and quality', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: 'flac' });

        // 凭证里是密文：肉眼看不出链接，也看不出 secret。
        expect(token).not.toContain('qqmusic.qq.com');
        expect(token).not.toContain('TESTVKEY');
        expect(token).not.toContain(SECRET);

        const payload = await unsealAudioPlayUrl(SECRET, token);
        expect(payload).toEqual({
            url: DIRECT_URL,
            mid: '003abc',
            quality: 'flac',
            exp: expect.any(Number),
        });
        expect(payload!.exp).toBeGreaterThan(Date.now());
        expect(payload!.exp).toBeLessThanOrEqual(Date.now() + AUDIO_PROXY_TOKEN_TTL_MS);
    });

    it('refuses a token sealed with another secret', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: '128' });

        await expect(unsealAudioPlayUrl(OTHER_SECRET, token)).resolves.toBeNull();
    });

    it('refuses garbage and tampered tokens', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: '128' });
        const tampered = `${token.slice(0, -2)}${token.endsWith('AA') ? 'BB' : 'AA'}`;

        await expect(unsealAudioPlayUrl(SECRET, 'not-a-token')).resolves.toBeNull();
        await expect(unsealAudioPlayUrl(SECRET, '')).resolves.toBeNull();
        await expect(unsealAudioPlayUrl(SECRET, tampered)).resolves.toBeNull();
    });
});

describe('QQ audio proxy route', () => {
    const fetchMock = vi.fn();

    beforeEach(() => {
        fetchMock.mockReset();
        vi.stubGlobal('fetch', fetchMock);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    it('ignores paths that are not the audio route', async () => {
        await expect(routeAudioProxy(
            audioRequest('https://folia.example/getMusicPlay/003abc'),
            ENV,
        )).resolves.toBeNull();
    });

    it('refuses non-GET requests on the audio route', async () => {
        const response = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=x`, { method: 'POST' }),
            ENV,
        );

        expect(response?.status).toBe(405);
    });

    it('answers 501 without a secret, like the library login routes', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: '128' });
        const response = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=${token}`),
            {},
        );

        expect(response?.status).toBe(501);
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('answers 400 without a token and for a bad token', async () => {
        const noToken = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}`),
            ENV,
        );
        const badToken = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=nope`),
            ENV,
        );

        expect(noToken?.status).toBe(400);
        expect(badToken?.status).toBe(400);
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('answers 410 once the token is past its expiry', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: '128' });
        const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + AUDIO_PROXY_TOKEN_TTL_MS + 1000);

        try {
            const response = await routeAudioProxy(
                audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=${token}`),
                ENV,
            );

            expect(response?.status).toBe(410);
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            nowSpy.mockRestore();
        }
    });

    it('streams the upstream audio back with Range and Referer, without buffering it', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: 'flac' });
        const upstreamBody = new ReadableStream({
            start(controller) {
                controller.enqueue(new TextEncoder().encode('audio-bytes'));
                controller.close();
            },
        });
        fetchMock.mockResolvedValue(new Response(upstreamBody, {
            status: 206,
            headers: {
                'content-type': 'audio/flac',
                'content-length': '11',
                'content-range': 'bytes 0-10/100',
                'accept-ranges': 'bytes',
            },
        }));

        const response = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=${token}`, {
                headers: { Range: 'bytes=0-10', 'User-Agent': 'TestAgent/1.0' },
            }),
            ENV,
        );

        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(fetchMock.mock.calls[0][0]).toBe(DIRECT_URL);
        const sentHeaders = fetchMock.mock.calls[0][1].headers as Record<string, string>;
        expect(sentHeaders.Range).toBe('bytes=0-10');
        expect(sentHeaders.Referer).toBe('https://y.qq.com');
        expect(sentHeaders['User-Agent']).toBe('TestAgent/1.0');

        expect(response?.status).toBe(206);
        expect(response?.headers.get('content-type')).toBe('audio/flac');
        expect(response?.headers.get('content-range')).toBe('bytes 0-10/100');
        expect(response?.headers.get('accept-ranges')).toBe('bytes');
        expect(response?.headers.get('cache-control')).toBe('no-store');
        expect(await response?.text()).toBe('audio-bytes');
    });

    it('passes an upstream refusal through as its status, without a body', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: '128' });
        fetchMock.mockResolvedValue(new Response(null, { status: 403 }));

        const response = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=${token}`),
            ENV,
        );

        expect(response?.status).toBe(403);
        expect(await response?.text()).toBe('');
    });

    it('answers 502 when the upstream fetch itself fails', async () => {
        const token = await sealAudioPlayUrl(SECRET, { url: DIRECT_URL, mid: '003abc', quality: '128' });
        fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));

        const response = await routeAudioProxy(
            audioRequest(`https://folia.example${AUDIO_PROXY_PATH}?t=${token}`),
            ENV,
        );

        expect(response?.status).toBe(502);
    });
});

describe('QQ play URL rewriting', () => {
    const playRequest = (mid = '003abc', quality = 'flac') => audioRequest(
        `https://folia.example/getMusicPlay/${mid}?quality=${quality}`,
    );
    const PUBLIC_BASE = 'https://folia.example/api/qq';

    it('rewrites every non-empty play URL to the proxy and keeps the rest of the entry', async () => {
        const response = await rewritePlayUrlsToProxy(
            getMusicPlayResponse({
                '003abc': { url: DIRECT_URL, quality: 'flac' },
                '004def': { url: '', error: '暂无播放链接', restriction: { codes: { result: 0 } } },
            }),
            playRequest(),
            ENV,
            PUBLIC_BASE,
        );

        expect(response.status).toBe(200);
        const body = await response.json() as any;
        const rewritten = body.data.playUrl['003abc'].url as string;
        expect(rewritten.startsWith('https://folia.example/api/qq/audio?t=')).toBe(true);
        expect(rewritten).not.toContain('qqmusic.qq.com');
        expect(rewritten).not.toContain('TESTVKEY');
        expect(body.data.playUrl['003abc'].quality).toBe('flac');
        // 空链接原样保留：前端的「拿不到链接」诊断不受影响。
        expect(body.data.playUrl['004def']).toEqual({
            url: '',
            error: '暂无播放链接',
            restriction: { codes: { result: 0 } },
        });

        // 改写后的链接解开就是原来的直链（代理端点靠它取音频）。
        const token = new URL(rewritten).searchParams.get('t') ?? '';
        await expect(unsealAudioPlayUrl(SECRET, token)).resolves.toEqual({
            url: DIRECT_URL,
            mid: '003abc',
            quality: 'flac',
            exp: expect.any(Number),
        });
    });

    it('leaves other paths, error statuses, and responses without a secret untouched', async () => {
        const otherPath = await rewritePlayUrlsToProxy(
            getMusicPlayResponse({ '003abc': { url: DIRECT_URL } }),
            audioRequest('https://folia.example/getSongInfo/003abc'),
            ENV,
            PUBLIC_BASE,
        );
        expect(await otherPath.text()).toContain(DIRECT_URL);

        const errorStatus = await rewritePlayUrlsToProxy(
            new Response('{"code":401}', { status: 401 }),
            playRequest(),
            ENV,
            PUBLIC_BASE,
        );
        expect(errorStatus.status).toBe(401);

        const noSecret = await rewritePlayUrlsToProxy(
            getMusicPlayResponse({ '003abc': { url: DIRECT_URL } }),
            playRequest(),
            {},
            PUBLIC_BASE,
        );
        expect(await noSecret.text()).toContain(DIRECT_URL);
    });

    it('leaves a body without a play URL map byte-identical', async () => {
        const original = JSON.stringify({ code: 0, data: { message: 'no songmid' } });
        const response = await rewritePlayUrlsToProxy(
            new Response(original, { status: 200, headers: { 'content-type': 'application/json' } }),
            playRequest(),
            ENV,
            PUBLIC_BASE,
        );

        expect(await response.text()).toBe(original);
    });
});
