// shared/qqPhoneLogin.mjs
// QQ 音乐手机号验证码登录：Folia 侧的 serverless 层，Vercel（api-ts/qq.ts）与
// Cloudflare（worker/qq.ts）两个入口共用。
//
// 上游包 @yakult-green-tea/qq-music-api 3.3.6 没有这两个接口（它只导出 handleRequest），
// 所以这里直接读包内 dist-esm 的内部模块（callMusicu、QIMEI bootstrap、sealed 会话），
// 不改包里的任何文件；升级包版本时按 src/services/onlineMusic/UPSTREAMS.md 核对这些内部
// 路径与导出名。协议来源：~/workspace/folia-phone-login/protocol-spec.md（含附录 A，
// 已用 L-1124/QQMusicApi 原仓库核实：验证码字段名是 `code`，SendPhoneAuthCode 的
// SEND=0、CAPTCHA=20276、FREQUENCY=100001，CAPTCHA 时 data.securityURL 原样透传）。
//
// 安全：手机号、验证码、musickey、token 永不进日志（日志只记脱敏号与事件名）；
// 验证码只做一次性校验，不持久化明文；冷却状态只以手机号的 SHA-256 记在内存里。

import { buildAndroidComm, credentialMusicId } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/services/auth/androidDevice.js';
import { ensureQimei, refreshAndroidSession } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/services/auth/bootstrap.js';
import { credentialFrom } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/services/auth/credentialWire.js';
import { authSessionExpiryAt, credentialExpiryAt } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/services/auth/credentialExpiry.js';
import { callMusicu, MUSICU_URL, QqDeviceBootstrapError, QqProtocolError } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/services/auth/musicuProtocol.js';
import { deriveAndroidDevice } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/serverless/derivedDevice.js';
import { createSealedSessionResolver } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/serverless/sealedResolver.js';
import { createFetchAuthHttpClient } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/transport/fetchAuthHttpClient.js';
import { logger } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/util/logger.js';
import { dictionaryOf, numberOf, stringOf } from '../node_modules/@yakult-green-tea/qq-music-api/dist-esm/src/util/values.js';

export const PHONE_SEND_PATH = '/login/phone/send';
export const PHONE_VERIFY_PATH = '/login/phone/verify';
export const PHONE_CHANNELS_PATH = '/login/channels';

// 与上游 serverless/index.js 的 NO_SECRET 同文：无 secret 时登录路由一律 501。
export const NO_SECRET_MESSAGE = 'QQ_SESSION_SECRET is not set. Set it to enable login.';

export const PHONE_SEND_COOLDOWN_MS = 60_000;
export const PHONE_FREQUENCY_COOLDOWN_MS = 5 * 60_000;
export const PHONE_SEND_DAILY_LIMIT = 5;

// verify 失败限流：同一号码连续 5 次验证失败锁 5 分钟（429 + Retry-After，与 send 的
// recordFrequencyBlocked 同款写法）。只记失败次数，不记验证码本身。
export const PHONE_VERIFY_MAX_FAILURES = 5;
export const PHONE_VERIFY_LOCK_MS = 5 * 60_000;

// 上游 SendPhoneAuthCode 的 req_0.code（qqmusic_api/models/login.py：PhoneLoginEvents）。
export const PHONE_SEND_CODE = 0;
export const PHONE_CAPTCHA_CODE = 20276;
export const PHONE_FREQUENCY_CODE = 100001;

// phone_authorize 的业务错误码（qqmusic_api/modules/login.py：phone_authorize）。
const CREDENTIAL_REJECTED_CODES = new Set([1000, 104401, 104400]);
const ACCOUNT_RESTRICTED_CODES = new Set([20277, 20278, 20450]);
const DEVICE_LIMIT_CODE = 20279;
const RATE_LIMIT_CODE = 104604;

const PHONE_RE = /^1\d{10}$/;
const CODE_RE = /^\d{4,6}$/;
const COOLDOWN_STORE_LIMIT = 1000;

const jsonResponse = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
});

/** 手机号只回显脱敏形式；日志与回包都只用这个。 */
export const maskPhone = (phone) => `${phone.slice(0, 3)}****${phone.slice(7)}`;

/**
 * 凭证缺失 loginType 时的兜底：与 Python 的 Credential 推断一致（musickey 前缀
 * W_X_ → 微信 type 1，其余 → QQ type 2）。回包给了 loginType 时 credentialFrom
 * 优先用回包值，这个兜底不会覆盖它——标错类型会导致之后每次带凭证请求都被拒。
 */
export const defaultLoginTypeOf = (musickey) => (musickey.startsWith('W_X_') ? 1 : 2);

/**
 * 这份凭证以后能不能走 POST /login/refresh：与 sessionState.js 的
 * shouldRefreshStoredCredential 同条件（能算出 musickey 到期时间，且带非空
 * refresh_key）。sealed 下没有 refresh_key 的 token 永远回 rotated: false，
 * 会话最长只有 musickey 自身寿命（实测约 3 天，见 credentialExpiry.js）。
 */
export const isRefreshableCredential = (credential) =>
    credentialExpiryAt(credential) !== null && stringOf(credential.refresh_key).length > 0;

// 与 authenticatedReads.js 的 publicProfileFromCredential 同形状：只取凭证里的公开字段。
const publicProfileFromCredential = (credential) => {
    const musicId = credentialMusicId(credential);
    const nickname = stringOf(credential.nick) || stringOf(credential.nickname);
    const avatarUrl = stringOf(credential.logo) || stringOf(credential.avatarUrl);
    return {
        ...(musicId ? { musicid: musicId, str_musicid: musicId } : {}),
        ...(nickname ? { nickname, nick: nickname } : {}),
        ...(avatarUrl ? { avatarUrl } : {}),
    };
};

class PhoneLoginError extends Error {
    constructor(status, message, upstreamCode, retryAfterSeconds) {
        super(message);
        this.name = 'PhoneLoginError';
        this.status = status;
        this.upstreamCode = upstreamCode;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    toResponse() {
        const body = { code: this.status, message: this.message };
        if (this.upstreamCode !== undefined) body.upstreamCode = this.upstreamCode;
        const headers = this.retryAfterSeconds !== undefined
            ? { 'Retry-After': String(this.retryAfterSeconds) }
            : {};
        return jsonResponse(body, this.status, headers);
    }
}

const badRequest = (message) => new PhoneLoginError(400, message);
const upstreamFailure = (message, upstreamCode) => new PhoneLoginError(502, message, upstreamCode);

const isRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

async function readJsonBody(request) {
    let body;
    try {
        body = await request.json();
    } catch {
        throw badRequest('Invalid JSON body');
    }
    if (!isRecord(body)) throw badRequest('Invalid JSON body');
    return body;
}

// v1 只支持中国大陆 11 位号；countryCode 只接受 86（数字或字符串），其余明确拒绝。
function parsePhoneInput(body) {
    const countryCode = body.countryCode === undefined ? 86 : body.countryCode;
    if (countryCode !== 86 && countryCode !== '86') throw badRequest('Unsupported country code');
    const phone = body.phone;
    if (typeof phone !== 'string' || !PHONE_RE.test(phone)) throw badRequest('Invalid phone number');
    return { phone, countryCode: '86' };
}

/**
 * 每手机号发送冷却（只在内存里，isolate 之间不共享——与 QrLoginService 的
 * nextQrAllowedAt 同款局限；跨 isolate 的冷却靠上游 100001/104604 兜底）。
 * key 是手机号的 SHA-256，内存里不存明文号。
 *
 * verify 的失败限流记在同一张表里（同一号码、同一 key）：连续失败 5 次锁 5 分钟，
 * 成功一次就清零。同样只在 isolate 内有效，跨 isolate 靠上游 104604 兜底。
 * 后端不核对“先 send 后 verify”：验证码由上游持有、两次调用之间后端无状态
 * （协议规格 §2.4）；如需核对须引入服务端状态，超出本次范围。
 */
export function createCooldownStore() {
    const entries = new Map();
    const keyOf = async (phone) => {
        const digest = await globalThis.crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(`qq-phone-login:${phone}`),
        );
        return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    };
    const dayKeyOf = (nowMs) => new Date(nowMs).toISOString().slice(0, 10);
    const prune = () => {
        while (entries.size > COOLDOWN_STORE_LIMIT) entries.delete(entries.keys().next().value);
    };
    // 新建/续写一条记录时把 verify 的计数原样带上，别让 send 的写操作清掉它（反之亦然）。
    const withVerify = (prev, patch, nowMs) => ({
        sentAtMs: prev?.sentAtMs ?? 0,
        blockedUntilMs: prev?.blockedUntilMs ?? 0,
        dayKey: prev?.dayKey ?? dayKeyOf(nowMs),
        dayCount: prev?.dayCount ?? 0,
        verifyFailures: prev?.verifyFailures ?? 0,
        verifyBlockedUntilMs: prev?.verifyBlockedUntilMs ?? 0,
        ...patch,
    });
    return {
        async checkSend(phone, nowMs) {
            const entry = entries.get(await keyOf(phone));
            if (!entry) return { allowed: true };
            if (entry.blockedUntilMs > nowMs) {
                return { allowed: false, retryAfterSeconds: Math.ceil((entry.blockedUntilMs - nowMs) / 1000) };
            }
            if (nowMs - entry.sentAtMs < PHONE_SEND_COOLDOWN_MS) {
                return {
                    allowed: false,
                    retryAfterSeconds: Math.ceil((PHONE_SEND_COOLDOWN_MS - (nowMs - entry.sentAtMs)) / 1000),
                };
            }
            if (entry.dayKey === dayKeyOf(nowMs) && entry.dayCount >= PHONE_SEND_DAILY_LIMIT) {
                const nextMidnightMs = Date.parse(`${entry.dayKey}T00:00:00.000Z`) + 24 * 60 * 60 * 1000;
                return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((nextMidnightMs - nowMs) / 1000)) };
            }
            return { allowed: true };
        },
        async recordSent(phone, nowMs) {
            const key = await keyOf(phone);
            const dayKey = dayKeyOf(nowMs);
            const prev = entries.get(key);
            entries.set(key, withVerify(prev, {
                sentAtMs: nowMs,
                dayKey,
                dayCount: prev && prev.dayKey === dayKey ? prev.dayCount + 1 : 1,
            }, nowMs));
            prune();
        },
        async recordFrequencyBlocked(phone, nowMs) {
            const key = await keyOf(phone);
            const prev = entries.get(key);
            entries.set(key, withVerify(prev, {
                blockedUntilMs: nowMs + PHONE_FREQUENCY_COOLDOWN_MS,
            }, nowMs));
            prune();
        },
        async checkVerify(phone, nowMs) {
            const entry = entries.get(await keyOf(phone));
            if (!entry || entry.verifyBlockedUntilMs <= nowMs) return { allowed: true };
            return {
                allowed: false,
                retryAfterSeconds: Math.ceil((entry.verifyBlockedUntilMs - nowMs) / 1000),
            };
        },
        async recordVerifyFailed(phone, nowMs) {
            const key = await keyOf(phone);
            const prev = entries.get(key);
            const failures = (prev?.verifyFailures ?? 0) + 1;
            entries.set(key, withVerify(prev, failures >= PHONE_VERIFY_MAX_FAILURES
                ? { verifyFailures: 0, verifyBlockedUntilMs: nowMs + PHONE_VERIFY_LOCK_MS }
                : { verifyFailures: failures }, nowMs));
            prune();
        },
        async recordVerifySucceeded(phone, nowMs) {
            const key = await keyOf(phone);
            const prev = entries.get(key);
            if (!prev) return;
            entries.set(key, withVerify(prev, { verifyFailures: 0, verifyBlockedUntilMs: 0 }, nowMs));
            prune();
        },
    };
}

// 一个 isolate 内共用的冷却表（与 QrLoginService 的进程内状态同一性质）。
const defaultCooldowns = createCooldownStore();

/**
 * 与扫码登录 createSession 相同的前置 bootstrap：QIMEI（24h 内复用）+ GetSession。
 * 设备是调用内现取的对象，不经过 deviceStore——serverless 下每次调用都从 secret
 * 派生同一设备身份，QIMEI 与 session 跨调用不保存，所以 send 与 verify 各跑一次。
 */
const defaultBootstrapDevice = async (http, device, nowMs) => {
    await ensureQimei(http, device, nowMs);
    await refreshAndroidSession(http, device);
};

/**
 * SendPhoneAuthCode 不能直接用 callMusicu：它在上游码非 0 时抛错并丢掉 data，
 * 而 send 的语义要求把 code 当数据分支（CAPTCHA 时 data.securityURL 还要原样透传）。
 * 这里只复现 callMusicu 的请求构造（同一 comm、同一请求头），跳过“非 0 即抛”，
 * 原样返回 { code, globalCode, data, ok }。ok 只在全局码为 0 且 req_0 非空（带 code）
 * 时为 true——比 callMusicu 的“顶层与 req_0 均为 0 才成功”只宽在“非 0 码当数据分支”，
 * 全局码非 0 或 req_0 为空时不判 SEND，由调用方按上游错误走 502。
 */
export const defaultSendAuthCodeRaw = async (http, device, phone, countryCode) => {
    const response = await http.post(MUSICU_URL, {
        comm: buildAndroidComm(device, undefined, { tmeLoginMethod: 3 }),
        req_0: {
            module: 'music.login.LoginServer',
            method: 'SendPhoneAuthCode',
            param: { tmeAppid: 'qqmusic', areaCode: countryCode, phoneNo: phone },
        },
    }, {
        headers: { 'User-Agent': `QQMusic 14090008(android ${device.osRelease})` },
    });
    const body = dictionaryOf(response.data);
    const item = dictionaryOf(body.req_0);
    const globalCode = numberOf(body.code) ?? 0;
    const itemCode = numberOf(item.code);
    return {
        code: itemCode ?? globalCode,
        globalCode,
        data: dictionaryOf(item.data),
        ok: globalCode === 0 && Object.keys(item).length > 0 && itemCode !== undefined,
    };
};

// verify 的 Login 调用失败时按上游码映射（与现有凭证被拒的映射一致）。
const mapVerifyUpstreamError = (error) => {
    if (error instanceof QqProtocolError) {
        const code = error.upstreamCode;
        if (code !== undefined && CREDENTIAL_REJECTED_CODES.has(code)) {
            return new PhoneLoginError(401, 'Login required');
        }
        if (code !== undefined && (ACCOUNT_RESTRICTED_CODES.has(code) || code === DEVICE_LIMIT_CODE)) {
            return new PhoneLoginError(403, 'Login restricted', code);
        }
        if (code === RATE_LIMIT_CODE) {
            return new PhoneLoginError(429, 'Too many requests', code, 60);
        }
        return upstreamFailure('Unable to verify code', code);
    }
    if (error instanceof QqDeviceBootstrapError) {
        return upstreamFailure('Unable to verify code', error.outerCode ?? undefined);
    }
    return upstreamFailure('Unable to verify code');
};

/**
 * 手机号登录服务。ports 全部可注入：生产走库内默认实现，测试注入替身。
 * 每次调用都新建 http 客户端与派生设备（与 serverless/index.js 的 createServiceFor
 * 每次调用重建 service 同理：一个 isolate 可能服务多个请求，不能跨请求复用 cookie jar）。
 */
export function createPhoneLoginService(ports = {}, env = {}) {
    const now = ports.now ?? (() => Date.now());
    const secrets = { current: env.QQ_SESSION_SECRET ?? '', previous: env.QQ_SESSION_SECRET_PREVIOUS };
    const cooldowns = ports.cooldowns ?? defaultCooldowns;
    const createHttpClient = ports.createHttpClient ?? (() => createFetchAuthHttpClient());
    const deriveDevice = ports.deriveDevice ?? deriveAndroidDevice;
    const bootstrapDevice = ports.bootstrapDevice ?? defaultBootstrapDevice;
    const sendAuthCodeRaw = ports.sendAuthCodeRaw ?? defaultSendAuthCodeRaw;
    const callMusicuFn = ports.callMusicu ?? callMusicu;
    const credentialFromFn = ports.credentialFrom ?? credentialFrom;
    const expiryAtFn = ports.authSessionExpiryAt ?? authSessionExpiryAt;
    const createSessionResolver = ports.createSessionResolver
        ?? ((candidateSecrets) => createSealedSessionResolver({ secrets: candidateSecrets }));

    const bootstrap = async (nowMs, failureMessage) => {
        const http = createHttpClient();
        const device = await deriveDevice(secrets.current);
        try {
            await bootstrapDevice(http, device, nowMs);
        } catch (error) {
            if (error instanceof PhoneLoginError) throw error;
            if (error instanceof QqDeviceBootstrapError) {
                throw upstreamFailure(failureMessage, error.outerCode ?? undefined);
            }
            throw upstreamFailure(failureMessage);
        }
        return { http, device };
    };

    const send = async (request) => {
        const { phone, countryCode } = parsePhoneInput(await readJsonBody(request));
        const masked = maskPhone(phone);
        const nowMs = now();
        const cooldown = await cooldowns.checkSend(phone, nowMs);
        if (!cooldown.allowed) {
            logger.info('qq-auth.phone-send-cooldown', { phone: masked, retryAfterSeconds: cooldown.retryAfterSeconds });
            throw new PhoneLoginError(429, 'Too many requests', undefined, cooldown.retryAfterSeconds);
        }
        const { http, device } = await bootstrap(nowMs, 'Unable to send verification code');
        let result;
        try {
            result = await sendAuthCodeRaw(http, device, phone, countryCode);
        } catch (error) {
            if (error instanceof PhoneLoginError) throw error;
            if (error instanceof QqDeviceBootstrapError) {
                throw upstreamFailure('Unable to send verification code', error.outerCode ?? undefined);
            }
            throw upstreamFailure('Unable to send verification code');
        }
        logger.info('qq-auth.phone-send-result', { phone: masked, code: result.code });
        // 上游原始回包不可用（全局码非 0、或 req_0 为空）：不按 code 分支，直接按上游错误走 502。
        // 注入的 sendAuthCodeRaw 替身不带 ok 时（ok 为 undefined）照旧分支，不破坏已有调用方。
        if (result.ok === false) {
            throw upstreamFailure('Unable to send verification code', result.code || undefined);
        }
        if (result.code === PHONE_SEND_CODE) {
            await cooldowns.recordSent(phone, nowMs);
            return {
                status: 200,
                body: { code: 200, data: { event: 'sent', phone: masked } },
            };
        }
        if (result.code === PHONE_CAPTCHA_CODE) {
            const securityUrl = stringOf(dictionaryOf(result.data).securityURL) || undefined;
            return {
                status: 200,
                body: {
                    code: 200,
                    data: { event: 'captcha_required', ...(securityUrl ? { securityUrl } : {}) },
                },
            };
        }
        if (result.code === PHONE_FREQUENCY_CODE) {
            await cooldowns.recordFrequencyBlocked(phone, nowMs);
            throw new PhoneLoginError(429, 'Too many requests', PHONE_FREQUENCY_CODE, 60);
        }
        throw upstreamFailure('Unable to send verification code', result.code);
    };

    const verify = async (request) => {
        const body = await readJsonBody(request);
        const { phone } = parsePhoneInput(body);
        // 验证码字段名：上游 Login 的 param 字段是 `code`（协议规格附录 A.2）；规格 §5.2 示例
        // 写的 `authCode` 也接受，两者同时给时以 `code` 为准。
        const code = body.code ?? body.authCode;
        if (typeof code !== 'string' || !CODE_RE.test(code)) throw badRequest('Invalid verification code');
        const masked = maskPhone(phone);
        const nowMs = now();
        // verify 也限流：同一号码连续失败 5 次锁 5 分钟（429 + Retry-After），在发上游之前就拦。
        const verifyCooldown = await cooldowns.checkVerify(phone, nowMs);
        if (!verifyCooldown.allowed) {
            logger.info('qq-auth.phone-verify-cooldown', { phone: masked, retryAfterSeconds: verifyCooldown.retryAfterSeconds });
            throw new PhoneLoginError(429, 'Too many requests', undefined, verifyCooldown.retryAfterSeconds);
        }
        const { http, device } = await bootstrap(nowMs, 'Unable to verify code');
        let credential;
        // 换凭证与校验凭证两步里任何一步失败都算一次验证失败（次数进冷却表，成功则清零）。
        try {
            const data = await callMusicuFn(http, device, 'phone-verify', 'music.login.LoginServer', 'Login', {
                code,
                loginMode: 1,
                phoneNo: phone,
            }, undefined, { tmeLoginMethod: 3, tmeLoginType: 0 });
            const fields = dictionaryOf(data);
            credential = credentialFromFn(fields, defaultLoginTypeOf(stringOf(fields.musickey)));
            // 发会话前校验一次凭证（GetLoginUserInfo，与 finalizeLogin 校验微信凭证同一调用），
            // 结果本身不进回包，只确认凭证可用。
            await callMusicuFn(http, device, 'get-login-user', 'music.UserInfo.userInfoServer', 'GetLoginUserInfo', {}, credential);
        } catch (error) {
            await cooldowns.recordVerifyFailed(phone, nowMs);
            throw mapVerifyUpstreamError(error);
        }
        await cooldowns.recordVerifySucceeded(phone, nowMs);
        const resolver = createSessionResolver(secrets);
        const expiresAt = expiryAtFn(credential, nowMs);
        const token = await resolver.issue({ credential, device, expiresAt });
        const refreshable = isRefreshableCredential(credential);
        logger.info('qq-auth.phone-login-confirmed', {
            phone: masked,
            credentialLoginType: credential.loginType,
            refreshable,
        });
        return {
            status: 200,
            body: {
                code: 200,
                data: {
                    token,
                    expiresAt,
                    rotated: false,
                    profile: publicProfileFromCredential(credential),
                    refreshable,
                },
            },
        };
    };

    return { send, verify };
}

/**
 * 两个 serverless 入口的 phone 路由分发：是 phone 路径时返回 Response，
 * 不是时返回 null（调用方原样交给上游 handleRequest，body 不会被读掉）。
 * 非 POST 回 405；无 secret 回 501（与库内 needsSecret 路由一致）。
 */
export async function routePhoneLogin(request, env = {}, ports = {}) {
    const pathname = new URL(request.url).pathname;
    if (pathname !== PHONE_SEND_PATH && pathname !== PHONE_VERIFY_PATH) return null;
    try {
        if (request.method !== 'POST') {
            return jsonResponse({ code: 405, message: 'POST required' }, 405, { Allow: 'POST' });
        }
        if (!env.QQ_SESSION_SECRET) {
            return jsonResponse({ code: 501, message: NO_SECRET_MESSAGE }, 501);
        }
        const service = createPhoneLoginService(ports, env);
        const result = pathname === PHONE_SEND_PATH ? await service.send(request) : await service.verify(request);
        return jsonResponse(result.body, result.status, result.headers ?? {});
    } catch (error) {
        if (error instanceof PhoneLoginError) return error.toResponse();
        // 未预期的错误不把内部细节带出去；日志里只记名字，不记请求体。
        logger.warn('qq-auth.phone-login-unexpected', { name: error instanceof Error ? error.name : 'Error' });
        return jsonResponse({ code: 500, message: 'Internal error' }, 500);
    }
}

/**
 * GET /login/channels 的回包里加独立能力位 features.auth.phoneLogin（方案 A）：
 * phone 不是 QR 通道，绝不进 channels 数组（会污染 createSession 的 QR 校验）。
 * 只在 secret 已配置时宣告——无 secret 时登录路由本来就回 501，宣告了也没用。
 * 非 channels 请求、无 secret、或回包形状不对时原样返回。
 */
export async function withPhoneLoginChannels(response, request, env = {}) {
    const url = new URL(request.url);
    if (request.method !== 'GET'
        || (url.pathname !== PHONE_CHANNELS_PATH && url.pathname !== `${PHONE_CHANNELS_PATH}/`)
        || !env.QQ_SESSION_SECRET) {
        return response;
    }
    let body;
    try {
        body = await response.json();
    } catch {
        return response;
    }
    if (!isRecord(body?.data) || !isRecord(body.data.features) || !isRecord(body.data.features.auth)) {
        return response;
    }
    // 只改 body：上游原响应头原样透传，只丢掉重建后一定会变的 content-type/content-length
    //（新 body 的长度与原响应不同，旧值留下来是错的）。
    const headers = {};
    response.headers.forEach((value, name) => {
        if (name !== 'content-type' && name !== 'content-length') headers[name] = value;
    });
    return jsonResponse({
        ...body,
        data: {
            ...body.data,
            features: {
                ...body.data.features,
                auth: { ...body.data.features.auth, phoneLogin: true },
            },
        },
    }, response.status, headers);
}
