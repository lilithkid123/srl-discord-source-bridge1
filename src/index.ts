interface Env {
  DB: D1Database
  DISCORD_APPLICATION_ID: string
  DISCORD_PUBLIC_KEY: string
  DISCORD_BOT_TOKEN: string
  HANDOFF_TTL_SECONDS?: string
  SRL_WEB_URL?: string
}

interface DiscordInteraction {
  type: number
  guild_id?: string
  channel_id?: string
  channel?: Record<string, unknown>
  data?: {
    type?: number
    target_id?: string
    resolved?: {
      messages?: Record<string, Record<string, unknown>>
    }
  }
}

type DiscordSourceRemoteScanCursor =
  | {
      lastSeenMessageId: string
      pendingBeforeMessageId?: never
      pendingHighWaterMessageId?: never
    }
  | {
      lastSeenMessageId: string
      pendingBeforeMessageId: string
      pendingHighWaterMessageId: string
    }

interface DiscordSourceReadRequest {
  guildId?: string
  channelId: string
  threadId?: string
  starterMessageId?: string
  savedMessageIds: string[]
  scanMessageIds: string[]
  scanCursor?: DiscordSourceRemoteScanCursor
}

interface DiscordSavedMessageCheckRequest {
  guildId?: string
  channelId: string
  threadId?: string
  starterMessageId?: string
  messageIds: string[]
}

interface DiscordCaptureContext {
  guildId?: string
  guildName?: string
  channelId: string
  channelName?: string
  threadId?: string
  starterMessageId: string
  title?: string
  forumTags: string[]
}

interface ThreadParentMetadata {
  channelName?: string
  forumTags: string[]
}

interface DiscordGuildMetadata {
  name?: string
  access: 'available' | 'unavailable' | 'unknown'
}

type DiscordSourceReadFailure =
  | { state: 'unavailable'; reason: 'not_found'; stage: 'channel' | 'starter' }
  | {
      state: 'uncheckable'
      reason: 'bot_access' | 'forbidden' | 'read_failed'
      stage: 'channel' | 'starter' | 'messages' | 'saved_messages'
    }

const COMMAND_NAME = '保存到资源库'
const THREAD_CHANNEL_TYPES = new Set([10, 11, 12])
const DISCORD_SNOWFLAKE_PATTERN = /^\d{5,32}$/u
const MAX_THREAD_PAGES = 3
const MAX_SAVED_MESSAGE_IDS = 24
const MAX_HEALTH_MESSAGE_IDS = 12
const HEALTH_CHECK_CONCURRENCY = 2
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
}

class DiscordRateLimitError extends Error {
  readonly retryAfterMs?: number

  constructor(operation: string, retryAfterMs?: number) {
    super(`${operation} rate limited`)
    this.name = 'DiscordRateLimitError'
    this.retryAfterMs = retryAfterMs
  }
}

function json(value: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'application/json; charset=utf-8')
  for (const [key, item] of Object.entries(CORS_HEADERS)) headers.set(key, item)
  return new Response(JSON.stringify(value), { ...init, headers })
}

function html(value: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'text/html; charset=utf-8')
  return new Response(value, { ...init, headers })
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/gu,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] ??
      character,
  )
}

function hexToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[0-9a-f]+$/iu.test(value) || value.length % 2 !== 0) throw new Error('invalid hex')
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return bytesToHex(new Uint8Array(digest))
}

async function verifyDiscordRequest(request: Request, rawBody: string, publicKeyHex: string) {
  const signature = request.headers.get('X-Signature-Ed25519')
  const timestamp = request.headers.get('X-Signature-Timestamp')
  if (!signature || !timestamp) return false
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      hexToBytes(publicKeyHex.trim()),
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    const message = new TextEncoder().encode(`${timestamp}${rawBody}`)
    return crypto.subtle.verify('Ed25519', key, hexToBytes(signature), message)
  } catch {
    return false
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function readForumTags(channel?: Record<string, unknown>): string[] {
  if (!channel) return []
  const applied = Array.isArray(channel.applied_tags)
    ? channel.applied_tags.filter((value): value is string => typeof value === 'string')
    : []
  const available = Array.isArray(channel.available_tags)
    ? channel.available_tags.flatMap((value) => {
        const tag = asRecord(value)
        const id = asString(tag?.id)
        const name = asString(tag?.name)
        return id && name ? [{ id, name }] : []
      })
    : []
  const names = new Map(available.map((tag) => [tag.id, tag.name]))
  return applied.flatMap((id) => {
    const name = names.get(id)
    return name ? [name] : []
  })
}

function normalizeAttachments(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return []
  return value.flatMap((item) => {
    const attachment = asRecord(item)
    if (!attachment) return []
    const id = asString(attachment.id)
    const name = asString(attachment.filename)
    const url = asString(attachment.url)
    if (!id || !name || !url) return []
    return [
      {
        id,
        name,
        size: asNumber(attachment.size) ?? 0,
        url,
        ...(asString(attachment.proxy_url) ? { proxyUrl: asString(attachment.proxy_url) } : {}),
        ...(asString(attachment.content_type)
          ? { contentType: asString(attachment.content_type) }
          : {}),
        ...(asNumber(attachment.width) !== undefined ? { width: asNumber(attachment.width) } : {}),
        ...(asNumber(attachment.height) !== undefined
          ? { height: asNumber(attachment.height) }
          : {}),
      },
    ]
  })
}

function buildCapture(interaction: DiscordInteraction): Record<string, unknown> {
  const channelId = interaction.channel_id ?? ''
  const targetId = interaction.data?.target_id ?? ''
  const message = interaction.data?.resolved?.messages?.[targetId]
  if (!channelId || !targetId || !message) throw new Error('Discord 没有提供被选中的消息')

  const author = asRecord(message.author)
  const authorId = asString(author?.id)
  const authorName =
    asString(author?.global_name) || asString(author?.username) || asString(message.author_name)
  if (!authorId || !authorName) throw new Error('无法读取消息作者')
  const authorBot = author?.bot === true || Boolean(asString(message.webhook_id))

  const channel = interaction.channel
  const channelType = asNumber(channel?.type)
  const threadId =
    channelType !== undefined && THREAD_CHANNEL_TYPES.has(channelType) ? channelId : undefined
  const starterMessageId = threadId ?? targetId
  const isStarter = targetId === starterMessageId
  const guildPath = interaction.guild_id ?? '@me'
  const canonicalUrl = `https://discord.com/channels/${encodeURIComponent(guildPath)}/${encodeURIComponent(channelId)}/${encodeURIComponent(targetId)}`
  const currentChannelName = asString(channel?.name) || undefined

  return {
    ...(interaction.guild_id ? { guildId: interaction.guild_id } : {}),
    channelId,
    ...(!threadId && currentChannelName ? { channelName: currentChannelName } : {}),
    ...(threadId ? { threadId } : {}),
    starterMessageId,
    isStarter,
    messageId: targetId,
    canonicalUrl,
    authorId,
    authorName,
    authorBot,
    content: typeof message.content === 'string' ? message.content : '',
    timestamp: asString(message.timestamp) || new Date().toISOString(),
    ...(asString(message.edited_timestamp)
      ? { editedTimestamp: asString(message.edited_timestamp) }
      : {}),
    ...(threadId && currentChannelName ? { title: currentChannelName } : {}),
    forumTags: readForumTags(channel),
    embeds: Array.isArray(message.embeds)
      ? message.embeds.filter((value) => Boolean(asRecord(value)))
      : [],
    attachments: normalizeAttachments(message.attachments),
  }
}

function handoffTtlSeconds(env: Env): number {
  const configured = Number(env.HANDOFF_TTL_SECONDS)
  return Number.isFinite(configured)
    ? Math.min(1_800, Math.max(300, Math.round(configured)))
    : 1_200
}

async function cleanupExpired(env: Env): Promise<void> {
  const now = Date.now()
  await env.DB.prepare(
    'DELETE FROM handoffs WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)',
  )
    .bind(now, now - 60_000)
    .run()
}

async function createHandoff(env: Env, payload: unknown): Promise<string> {
  const token = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
  const tokenHash = await sha256Hex(token)
  const now = Date.now()
  await env.DB.prepare(
    'INSERT INTO handoffs (token_hash, payload, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, NULL)',
  )
    .bind(tokenHash, JSON.stringify(payload), now, now + handoffTtlSeconds(env) * 1_000)
    .run()
  return token
}

async function consumeHandoff(env: Env, token: string): Promise<Response> {
  if (!/^[A-Za-z0-9_-]{30,160}$/u.test(token))
    return json({ error: 'invalid_token' }, { status: 400 })
  const tokenHash = await sha256Hex(token)
  const now = Date.now()
  const row = await env.DB.prepare(
    'SELECT payload FROM handoffs WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1',
  )
    .bind(tokenHash, now)
    .first<{ payload: string }>()
  if (!row) return json({ error: 'handoff_not_found_or_expired' }, { status: 404 })

  const claimed = await env.DB.prepare(
    'UPDATE handoffs SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?',
  )
    .bind(now, tokenHash, now)
    .run()
  if ((claimed.meta.changes ?? 0) !== 1)
    return json({ error: 'handoff_already_consumed' }, { status: 409 })

  try {
    return json({ capture: JSON.parse(row.payload) })
  } catch {
    return json({ error: 'handoff_payload_invalid' }, { status: 500 })
  }
}

function discordApplicationCommandsUrl(env: Env): string {
  return `https://discord.com/api/v10/applications/${encodeURIComponent(env.DISCORD_APPLICATION_ID)}/commands`
}

async function registerMessageCommand(env: Env): Promise<void> {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) {
    throw new Error('Discord Application ID / Bot Token 未配置')
  }
  const response = await fetch(discordApplicationCommandsUrl(env), {
    method: 'POST',
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: COMMAND_NAME,
      type: 3,
      integration_types: [1],
      contexts: [0, 1, 2],
    }),
  })
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 800)
    throw new Error(`Discord command registration failed: ${response.status} ${detail}`)
  }
}

async function readMessageCommandStatus(env: Env): Promise<boolean> {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) {
    throw new Error('Discord Application ID / Bot Token 未配置')
  }
  const response = await fetch(discordApplicationCommandsUrl(env), {
    method: 'GET',
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  })
  const payload = await discordJson(response, 'Discord command status read')
  if (!Array.isArray(payload)) throw new Error('Discord command status response invalid')
  return payload.some((item) => {
    const command = asRecord(item)
    return asString(command?.name) === COMMAND_NAME && asNumber(command?.type) === 3
  })
}

function authorizedSetup(request: Request, env: Env): boolean {
  const header = request.headers.get('Authorization') ?? ''
  return Boolean(env.DISCORD_BOT_TOKEN) && header === `Bearer ${env.DISCORD_BOT_TOKEN}`
}

function validSnowflake(value: string | undefined): value is string {
  return Boolean(value && DISCORD_SNOWFLAKE_PATTERN.test(value))
}

function compareSnowflakes(left: string, right: string): number {
  const a = BigInt(left)
  const b = BigInt(right)
  return a < b ? -1 : a > b ? 1 : 0
}

function parseScanCursor(value: unknown): DiscordSourceRemoteScanCursor | undefined {
  const record = asRecord(value)
  if (!record) return undefined
  const lastSeenMessageId = asString(record.lastSeenMessageId).trim() || undefined
  const pendingBeforeMessageId = asString(record.pendingBeforeMessageId).trim() || undefined
  const pendingHighWaterMessageId = asString(record.pendingHighWaterMessageId).trim() || undefined
  if (lastSeenMessageId && !validSnowflake(lastSeenMessageId)) return undefined
  if (pendingBeforeMessageId && !validSnowflake(pendingBeforeMessageId)) return undefined
  if (pendingHighWaterMessageId && !validSnowflake(pendingHighWaterMessageId)) return undefined
  if (pendingBeforeMessageId || pendingHighWaterMessageId) {
    if (!lastSeenMessageId || !pendingBeforeMessageId || !pendingHighWaterMessageId)
      return undefined
  }
  if (!lastSeenMessageId && !pendingBeforeMessageId && !pendingHighWaterMessageId) return undefined
  if (lastSeenMessageId && pendingBeforeMessageId && pendingHighWaterMessageId) {
    return { lastSeenMessageId, pendingBeforeMessageId, pendingHighWaterMessageId }
  }
  return lastSeenMessageId ? { lastSeenMessageId } : undefined
}

function parseSourceReadRequest(value: unknown): DiscordSourceReadRequest | undefined {
  const record = asRecord(value)
  if (!record) return undefined
  const channelId = asString(record.channelId).trim()
  const guildId = asString(record.guildId).trim() || undefined
  const threadId = asString(record.threadId).trim() || undefined
  const starterMessageId = asString(record.starterMessageId).trim() || undefined
  if (!validSnowflake(channelId)) return undefined
  if (guildId && !validSnowflake(guildId)) return undefined
  if (threadId && !validSnowflake(threadId)) return undefined
  if (starterMessageId && !validSnowflake(starterMessageId)) return undefined
  const savedMessageIds = Array.isArray(record.savedMessageIds)
    ? Array.from(
        new Set(
          record.savedMessageIds
            .filter((item): item is string => typeof item === 'string')
            .map((item) => item.trim())
            .filter((item) => DISCORD_SNOWFLAKE_PATTERN.test(item)),
        ),
      ).slice(0, MAX_SAVED_MESSAGE_IDS)
    : []
  const scanMessageIds = Array.isArray(record.scanMessageIds)
    ? Array.from(
        new Set(
          record.scanMessageIds
            .filter((item): item is string => typeof item === 'string')
            .map((item) => item.trim())
            .filter((item) => DISCORD_SNOWFLAKE_PATTERN.test(item)),
        ),
      ).slice(0, MAX_HEALTH_MESSAGE_IDS)
    : []
  const scanCursor = parseScanCursor(record.scanCursor)
  return {
    guildId,
    channelId,
    threadId,
    starterMessageId,
    savedMessageIds,
    scanMessageIds,
    scanCursor,
  }
}

function parseSavedMessageCheckRequest(
  value: unknown,
): DiscordSavedMessageCheckRequest | undefined {
  const record = asRecord(value)
  if (!record) return undefined
  const channelId = asString(record.channelId).trim()
  const guildId = asString(record.guildId).trim() || undefined
  const threadId = asString(record.threadId).trim() || undefined
  const starterMessageId = asString(record.starterMessageId).trim() || undefined
  if (!validSnowflake(channelId)) return undefined
  if (guildId && !validSnowflake(guildId)) return undefined
  if (threadId && !validSnowflake(threadId)) return undefined
  if (starterMessageId && !validSnowflake(starterMessageId)) return undefined
  const messageIds = Array.isArray(record.messageIds)
    ? Array.from(
        new Set(
          record.messageIds
            .filter((item): item is string => typeof item === 'string')
            .map((item) => item.trim())
            .filter((item) => DISCORD_SNOWFLAKE_PATTERN.test(item)),
        ),
      ).slice(0, MAX_HEALTH_MESSAGE_IDS)
    : []
  if (!messageIds.length) return undefined
  return { guildId, channelId, threadId, starterMessageId, messageIds }
}

async function discordApi(env: Env, path: string): Promise<Response> {
  return fetch(`https://discord.com/api/v10${path}`, {
    method: 'GET',
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  })
}

function retryAfterMs(response: Response): number | undefined {
  const header =
    response.headers.get('Retry-After') ?? response.headers.get('X-RateLimit-Reset-After')
  if (!header) return undefined
  const value = Number(header)
  if (!Number.isFinite(value) || value < 0) return undefined
  return Math.round(value * 1_000)
}

async function discordJson(response: Response, operation: string): Promise<unknown> {
  if (response.status === 429) throw new DiscordRateLimitError(operation, retryAfterMs(response))
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 500)
    throw new Error(`${operation} failed: ${response.status} ${detail}`)
  }
  return response.json()
}

async function readGuildMetadata(
  env: Env,
  guildId: string | undefined,
): Promise<DiscordGuildMetadata> {
  if (!validSnowflake(guildId)) return { access: 'unavailable' }
  const response = await discordApi(env, `/guilds/${encodeURIComponent(guildId)}`)
  if (response.status === 403 || response.status === 404) return { access: 'unavailable' }
  if (!response.ok) return { access: 'unknown' }
  const guild = asRecord(await response.json())
  const name = asString(guild?.name)
  return {
    access: 'available',
    ...(name ? { name } : {}),
  }
}

async function readThreadParentMetadata(
  env: Env,
  thread: Record<string, unknown>,
): Promise<ThreadParentMetadata> {
  const parentId = asString(thread.parent_id)
  if (!validSnowflake(parentId)) return { forumTags: [] }
  const response = await discordApi(env, `/channels/${encodeURIComponent(parentId)}`)
  if (!response.ok) return { forumTags: [] }
  const parent = asRecord(await response.json())
  if (!parent) return { forumTags: [] }
  const applied = Array.isArray(thread.applied_tags)
    ? thread.applied_tags.filter((item): item is string => typeof item === 'string')
    : []
  return {
    channelName: asString(parent.name) || undefined,
    forumTags: readForumTags({ ...parent, applied_tags: applied }),
  }
}

function buildCaptureFromMessage(
  message: Record<string, unknown>,
  context: DiscordCaptureContext,
): Record<string, unknown> | undefined {
  const messageId = asString(message.id)
  if (!validSnowflake(messageId)) return undefined
  const author = asRecord(message.author)
  const authorId = asString(author?.id)
  const authorName =
    asString(author?.global_name) || asString(author?.username) || asString(message.author_name)
  if (!validSnowflake(authorId) || !authorName) return undefined
  const authorBot = author?.bot === true || Boolean(asString(message.webhook_id))
  const guildPath = context.guildId ?? '@me'
  const canonicalUrl = `https://discord.com/channels/${encodeURIComponent(guildPath)}/${encodeURIComponent(context.channelId)}/${encodeURIComponent(messageId)}`
  const isStarter = messageId === context.starterMessageId
  return {
    ...(context.guildId ? { guildId: context.guildId } : {}),
    ...(context.guildName ? { guildName: context.guildName } : {}),
    channelId: context.channelId,
    ...(context.channelName ? { channelName: context.channelName } : {}),
    ...(context.threadId ? { threadId: context.threadId } : {}),
    starterMessageId: context.starterMessageId,
    isStarter,
    messageId,
    canonicalUrl,
    authorId,
    authorName,
    authorBot,
    content: typeof message.content === 'string' ? message.content : '',
    timestamp: asString(message.timestamp) || new Date().toISOString(),
    ...(asString(message.edited_timestamp)
      ? { editedTimestamp: asString(message.edited_timestamp) }
      : {}),
    ...(isStarter && context.title ? { title: context.title } : {}),
    forumTags: isStarter ? context.forumTags : [],
    embeds: Array.isArray(message.embeds)
      ? message.embeds.filter((value) => Boolean(asRecord(value)))
      : [],
    attachments: normalizeAttachments(message.attachments),
  }
}

function recordsFromMessageList(payload: unknown): Record<string, unknown>[] {
  if (!Array.isArray(payload)) throw new Error('Discord thread messages response invalid')
  return payload.flatMap((item) => {
    const message = asRecord(item)
    return message ? [message] : []
  })
}

function buildInitialThreadQuery(scanCursor: DiscordSourceRemoteScanCursor | undefined): string {
  const query = new URLSearchParams({ limit: '100' })
  if (scanCursor?.pendingBeforeMessageId) {
    query.set('before', scanCursor.pendingBeforeMessageId)
  } else if (scanCursor?.lastSeenMessageId) {
    query.set('after', scanCursor.lastSeenMessageId)
  }
  return query.toString()
}

function nextScanCursor(
  inputCursor: DiscordSourceRemoteScanCursor | undefined,
  highWaterMessageId: string | undefined,
  nextBeforeMessageId: string | undefined,
): DiscordSourceRemoteScanCursor | undefined {
  if (!highWaterMessageId) return inputCursor
  if (nextBeforeMessageId && inputCursor?.lastSeenMessageId) {
    return {
      lastSeenMessageId: inputCursor.lastSeenMessageId,
      pendingBeforeMessageId: nextBeforeMessageId,
      pendingHighWaterMessageId: inputCursor.pendingHighWaterMessageId ?? highWaterMessageId,
    }
  }
  return { lastSeenMessageId: inputCursor?.pendingHighWaterMessageId ?? highWaterMessageId }
}

async function readSourceMessages(
  env: Env,
  input: DiscordSourceReadRequest,
): Promise<
  | {
      state: 'available'
      captures: Array<Record<string, unknown>>
      scanCursor?: DiscordSourceRemoteScanCursor
    }
  | DiscordSourceReadFailure
> {
  const channelId = input.threadId ?? input.channelId
  const [channelResponse, guildMetadata] = await Promise.all([
    discordApi(env, `/channels/${encodeURIComponent(channelId)}`),
    readGuildMetadata(env, input.guildId),
  ])
  if (channelResponse.status === 403) {
    return {
      state: 'uncheckable',
      reason: 'forbidden',
      stage: 'channel',
    }
  }
  if (channelResponse.status === 404) {
    if (guildMetadata.access === 'available') {
      return { state: 'unavailable', reason: 'not_found', stage: 'channel' }
    }
    return {
      state: 'uncheckable',
      reason: guildMetadata.access === 'unavailable' ? 'bot_access' : 'read_failed',
      stage: 'channel',
    }
  }
  const channel = asRecord(await discordJson(channelResponse, 'Discord channel read'))
  if (!channel) throw new Error('Discord channel response invalid')
  const channelType = asNumber(channel.type)
  const threadId =
    input.threadId ??
    (channelType !== undefined && THREAD_CHANNEL_TYPES.has(channelType) ? channelId : undefined)
  const starterMessageId = threadId ?? input.starterMessageId ?? input.savedMessageIds[0]
  if (!validSnowflake(starterMessageId))
    throw new Error('Discord source starter message is missing')

  const starterPromise = discordApi(
    env,
    `/channels/${encodeURIComponent(channelId)}/messages/${encodeURIComponent(starterMessageId)}`,
  )
  const parentMetadataPromise = threadId
    ? readThreadParentMetadata(env, channel)
    : Promise.resolve<ThreadParentMetadata>({
        channelName: asString(channel.name) || undefined,
        forumTags: [],
      })
  const firstPagePromise = threadId
    ? discordApi(
        env,
        `/channels/${encodeURIComponent(channelId)}/messages?${buildInitialThreadQuery(input.scanCursor)}`,
      )
    : Promise.resolve<Response | undefined>(undefined)

  const [starterResponse, parentMetadata, firstPageResponse] = await Promise.all([
    starterPromise,
    parentMetadataPromise,
    firstPagePromise,
  ])
  if (starterResponse.status === 403) {
    return {
      state: 'uncheckable',
      reason: 'forbidden',
      stage: 'starter',
    }
  }
  if (starterResponse.status === 404)
    return { state: 'unavailable', reason: 'not_found', stage: 'starter' }
  const starter = asRecord(await discordJson(starterResponse, 'Discord starter message read'))
  if (!starter) throw new Error('Discord starter message response invalid')

  const context: DiscordCaptureContext = {
    guildId: input.guildId,
    guildName: guildMetadata.name,
    channelId,
    channelName: parentMetadata.channelName,
    threadId,
    starterMessageId,
    title: threadId ? asString(channel.name) || undefined : undefined,
    forumTags: parentMetadata.forumTags,
  }

  const messages = new Map<string, Record<string, unknown>>()
  messages.set(starterMessageId, starter)
  const starterAuthorId = asString(asRecord(starter.author)?.id)
  let scanCursor = input.scanCursor

  if (threadId && firstPageResponse) {
    if (firstPageResponse.status === 403 || firstPageResponse.status === 404) {
      return {
        state: 'uncheckable',
        reason: firstPageResponse.status === 403 ? 'forbidden' : 'read_failed',
        stage: 'messages',
      }
    }
    let records = recordsFromMessageList(
      await discordJson(firstPageResponse, 'Discord thread messages read'),
    )
    const lowerBound = input.scanCursor?.lastSeenMessageId
    let highWaterMessageId = input.scanCursor?.pendingHighWaterMessageId
    let nextBeforeMessageId: string | undefined
    let completed = false

    for (let page = 0; page < MAX_THREAD_PAGES; page += 1) {
      if (!highWaterMessageId) {
        const newest = asString(records[0]?.id)
        if (validSnowflake(newest)) highWaterMessageId = newest
      }
      let crossedLowerBound = false
      for (const message of records) {
        const id = asString(message.id)
        if (!validSnowflake(id)) continue
        if (lowerBound && compareSnowflakes(id, lowerBound) <= 0) {
          crossedLowerBound = true
          continue
        }
        const author = asRecord(message.author)
        const authorId = asString(author?.id)
        const relevant =
          input.savedMessageIds.includes(id) ||
          input.scanMessageIds.includes(id) ||
          id === starterMessageId ||
          (starterAuthorId && authorId === starterAuthorId) ||
          author?.bot === true ||
          Boolean(asString(message.webhook_id))
        if (relevant) messages.set(id, message)
      }

      if (crossedLowerBound || records.length < 100) {
        completed = true
        break
      }
      const before = asString(records.at(-1)?.id)
      if (!validSnowflake(before)) {
        completed = true
        break
      }
      if (page + 1 >= MAX_THREAD_PAGES) {
        nextBeforeMessageId = before
        break
      }
      const query = new URLSearchParams({ limit: '100', before })
      const response = await discordApi(
        env,
        `/channels/${encodeURIComponent(channelId)}/messages?${query.toString()}`,
      )
      if (response.status === 403 || response.status === 404) {
        return {
          state: 'uncheckable',
          reason: response.status === 403 ? 'forbidden' : 'read_failed',
          stage: 'messages',
        }
      }
      records = recordsFromMessageList(await discordJson(response, 'Discord thread messages read'))
    }

    if (!lowerBound) {
      // 旧来源 / 首次读取保持原来的“最多最近 300 条”合同；完成这次有界 bootstrap 后
      // 只把最顶部 message 作为后续增量高水位，不尝试无限回扫历史。
      // 空 thread 极端情况下以 starter 作为稳定下界，避免下次又退回 bootstrap。
      const bootstrapHighWater = highWaterMessageId ?? starterMessageId
      scanCursor = { lastSeenMessageId: bootstrapHighWater }
    } else {
      scanCursor = nextScanCursor(
        input.scanCursor,
        highWaterMessageId,
        completed ? undefined : nextBeforeMessageId,
      )
    }
  }

  for (const messageId of input.savedMessageIds) {
    if (messages.has(messageId)) continue
    const response = await discordApi(
      env,
      `/channels/${encodeURIComponent(channelId)}/messages/${encodeURIComponent(messageId)}`,
    )
    if (response.status === 404) continue
    if (response.status === 403)
      return { state: 'uncheckable', reason: 'forbidden', stage: 'saved_messages' }
    const message = asRecord(await discordJson(response, 'Discord saved message read'))
    if (message) messages.set(messageId, message)
  }

  const captures = Array.from(messages.values()).flatMap((message) => {
    const capture = buildCaptureFromMessage(message, context)
    return capture ? [capture] : []
  })
  captures.sort((left, right) => {
    const leftTimestamp = Date.parse(asString(left.timestamp))
    const rightTimestamp = Date.parse(asString(right.timestamp))
    return leftTimestamp - rightTimestamp
  })
  return { state: 'available', captures, scanCursor }
}

async function readSavedMessageHealth(
  env: Env,
  input: DiscordSavedMessageCheckRequest,
): Promise<
  | {
      state: 'available'
      captures: Array<Record<string, unknown>>
      missingMessageIds: string[]
      checkedMessageIds: string[]
      rateLimited: boolean
      retryAfterMs?: number
    }
  | Extract<DiscordSourceReadFailure, { state: 'uncheckable' }>
> {
  const channelId = input.threadId ?? input.channelId
  const starterMessageId = input.starterMessageId ?? input.threadId ?? input.messageIds[0]
  if (!validSnowflake(starterMessageId))
    throw new Error('Discord source starter message is missing')

  const context: DiscordCaptureContext = {
    guildId: input.guildId,
    channelId,
    threadId: input.threadId,
    starterMessageId,
    forumTags: [],
  }
  const captures: Array<Record<string, unknown>> = []
  const missingMessageIds: string[] = []
  const checkedMessageIds: string[] = []
  let index = 0
  let stopped = false
  let forbidden = false
  let rateLimited = false
  let rateLimitDelay: number | undefined

  const worker = async () => {
    while (!stopped) {
      const current = index
      index += 1
      if (current >= input.messageIds.length) return
      const messageId = input.messageIds[current]
      if (!messageId) return
      const response = await discordApi(
        env,
        `/channels/${encodeURIComponent(channelId)}/messages/${encodeURIComponent(messageId)}`,
      )
      if (response.status === 429) {
        rateLimited = true
        rateLimitDelay = retryAfterMs(response)
        stopped = true
        return
      }
      if (response.status === 403) {
        forbidden = true
        stopped = true
        return
      }
      if (response.status === 404) {
        missingMessageIds.push(messageId)
        checkedMessageIds.push(messageId)
        continue
      }
      const message = asRecord(await discordJson(response, 'Discord saved message health read'))
      if (!message) throw new Error('Discord saved message response invalid')
      const capture = buildCaptureFromMessage(message, context)
      if (!capture) throw new Error('Discord saved message capture invalid')
      captures.push(capture)
      checkedMessageIds.push(messageId)
    }
  }

  await Promise.all(Array.from({ length: HEALTH_CHECK_CONCURRENCY }, () => worker()))
  if (forbidden) return { state: 'uncheckable', reason: 'forbidden', stage: 'saved_messages' }
  return {
    state: 'available',
    captures,
    missingMessageIds,
    checkedMessageIds,
    rateLimited,
    ...(rateLimitDelay !== undefined ? { retryAfterMs: rateLimitDelay } : {}),
  }
}

async function handleSourceRead(request: Request, env: Env): Promise<Response> {
  if (!authorizedSetup(request, env)) return json({ error: 'unauthorized' }, { status: 401 })
  let input: DiscordSourceReadRequest | undefined
  try {
    input = parseSourceReadRequest(await request.json())
  } catch {
    input = undefined
  }
  if (!input) return json({ error: 'invalid_source_request' }, { status: 400 })
  try {
    return json(await readSourceMessages(env, input))
  } catch (error) {
    if (error instanceof DiscordRateLimitError) {
      return json(
        { error: 'discord_rate_limited', retryAfterMs: error.retryAfterMs },
        { status: 429 },
      )
    }
    console.error('Discord source read failed', error)
    return json(
      { error: error instanceof Error ? error.message : 'source_read_failed' },
      { status: 502 },
    )
  }
}

async function handleSavedMessageCheck(request: Request, env: Env): Promise<Response> {
  if (!authorizedSetup(request, env)) return json({ error: 'unauthorized' }, { status: 401 })
  let input: DiscordSavedMessageCheckRequest | undefined
  try {
    input = parseSavedMessageCheckRequest(await request.json())
  } catch {
    input = undefined
  }
  if (!input) return json({ error: 'invalid_message_check_request' }, { status: 400 })
  try {
    return json(await readSavedMessageHealth(env, input))
  } catch (error) {
    console.error('Discord saved message health check failed', error)
    return json(
      { error: error instanceof Error ? error.message : 'message_check_failed' },
      { status: 502 },
    )
  }
}

function openPage(request: Request, env: Env, token: string): Response {
  if (!/^[A-Za-z0-9_-]{30,160}$/u.test(token)) return html('<h1>链接无效</h1>', { status: 400 })
  const origin = new URL(request.url).origin
  const nativeUrl = `srl://discord-source?worker=${encodeURIComponent(origin)}&token=${encodeURIComponent(token)}`
  let webUrl = ''
  if (env.SRL_WEB_URL) {
    try {
      const parsed = new URL(env.SRL_WEB_URL)
      parsed.searchParams.set('discordWorker', origin)
      parsed.searchParams.set('discordHandoff', token)
      webUrl = parsed.toString()
    } catch {
      webUrl = ''
    }
  }
  return html(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>打开 SRL</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:32px 20px;color:#173641;background:#f5fafb}h1{font-size:1.35rem}p{color:#647b83;line-height:1.65}.a{display:block;margin-top:12px;padding:12px 14px;border:1px solid #bfd0d4;border-radius:8px;color:#315e6d;text-decoration:none;font-weight:700}.hint{font-size:.82rem;color:#82949b}</style></head>
<body><h1>Discord 来源已接收</h1><p>消息正在你自己的 Worker 中临时等待领取。打开 SRL 后会写入本机资源库。</p>
<a class="a" href="${escapeHtml(nativeUrl)}">打开 SRL Android App</a>
${webUrl ? `<a class="a" href="${escapeHtml(webUrl)}">打开 SRL 网页 / PWA</a>` : ''}
<p class="hint">如果没有自动打开，请回到 SRL 的来源配置页继续领取。这个临时链接会自动过期。</p></body></html>`)
}

async function handleInteraction(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const rawBody = await request.text()
  if (!(await verifyDiscordRequest(request, rawBody, env.DISCORD_PUBLIC_KEY))) {
    return new Response('invalid request signature', { status: 401 })
  }

  let interaction: DiscordInteraction
  try {
    interaction = JSON.parse(rawBody) as DiscordInteraction
  } catch {
    return new Response('invalid json', { status: 400 })
  }

  if (interaction.type === 1) {
    return json({ type: 1 })
  }

  if (interaction.type !== 2 || interaction.data?.type !== 3) {
    return json({
      type: 4,
      data: { content: '这个命令只用于保存 Discord 消息。', flags: 64 },
    })
  }

  try {
    const capture = buildCapture(interaction)
    const token = await createHandoff(env, capture)
    const openUrl = `${new URL(request.url).origin}/open/${encodeURIComponent(token)}`
    ctx.waitUntil(cleanupExpired(env).catch((error) => console.error(error)))
    return json({
      type: 4,
      data: {
        content: '已完整接收这条消息。打开资源库后再选择关联到哪个资源。',
        flags: 64,
        components: [
          {
            type: 1,
            components: [{ type: 2, style: 5, label: '打开资源库', url: openUrl }],
          },
        ],
      },
    })
  } catch (error) {
    console.error(error)
    return json({
      type: 4,
      data: {
        content: `保存失败：${error instanceof Error ? error.message : '无法读取消息'}`,
        flags: 64,
      },
    })
  }
}

async function readRequestedApplicationId(request: Request): Promise<string | undefined> {
  try {
    const body = asRecord(await request.json())
    const applicationId = asString(body?.applicationId).trim()
    return applicationId || undefined
  } catch {
    return undefined
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)
    if (request.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: CORS_HEADERS })

    if (url.pathname === '/health' && request.method === 'GET') {
      try {
        await env.DB.prepare('SELECT 1').first()
        return json({
          ok: true,
          database: true,
          discordConfigured: Boolean(
            env.DISCORD_APPLICATION_ID && env.DISCORD_PUBLIC_KEY && env.DISCORD_BOT_TOKEN,
          ),
          applicationId: env.DISCORD_APPLICATION_ID || null,
          commandName: COMMAND_NAME,
        })
      } catch {
        return json({ ok: false, database: false }, { status: 503 })
      }
    }

    if (url.pathname === '/setup/status' && request.method === 'GET') {
      if (!authorizedSetup(request, env)) return json({ error: 'unauthorized' }, { status: 401 })
      try {
        return json({
          ok: true,
          applicationId: env.DISCORD_APPLICATION_ID,
          commandName: COMMAND_NAME,
          commandRegistered: await readMessageCommandStatus(env),
        })
      } catch (error) {
        return json(
          { error: error instanceof Error ? error.message : 'command_status_failed' },
          { status: 502 },
        )
      }
    }

    if (url.pathname === '/setup/register' && request.method === 'POST') {
      if (!authorizedSetup(request, env)) return json({ error: 'unauthorized' }, { status: 401 })
      const requestedApplicationId = await readRequestedApplicationId(request)
      if (requestedApplicationId && requestedApplicationId !== env.DISCORD_APPLICATION_ID) {
        return json(
          {
            error: 'application_id_mismatch',
            applicationId: env.DISCORD_APPLICATION_ID,
          },
          { status: 409 },
        )
      }
      try {
        await registerMessageCommand(env)
        return json({
          ok: true,
          applicationId: env.DISCORD_APPLICATION_ID,
          commandName: COMMAND_NAME,
          commandRegistered: true,
        })
      } catch (error) {
        return json(
          { error: error instanceof Error ? error.message : 'command_registration_failed' },
          { status: 502 },
        )
      }
    }

    if (url.pathname === '/source/read' && request.method === 'POST') {
      return handleSourceRead(request, env)
    }

    if (url.pathname === '/source/messages/check' && request.method === 'POST') {
      return handleSavedMessageCheck(request, env)
    }

    if (url.pathname === '/interactions' && request.method === 'POST') {
      return handleInteraction(request, env, ctx)
    }

    if (url.pathname.startsWith('/handoff/') && request.method === 'GET') {
      const token = decodeURIComponent(url.pathname.slice('/handoff/'.length))
      const response = await consumeHandoff(env, token)
      ctx.waitUntil(cleanupExpired(env).catch((error) => console.error(error)))
      return response
    }

    if (url.pathname.startsWith('/open/') && request.method === 'GET') {
      return openPage(request, env, decodeURIComponent(url.pathname.slice('/open/'.length)))
    }

    if (url.pathname === '/' && request.method === 'GET') {
      return html(
        `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SRL Discord Bridge</title></head><body style="font-family:system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 20px;color:#173641"><h1>SRL Discord Bridge</h1><p>这个 Worker 只负责 Discord 消息的短期 handoff 与用户主动发起的只读来源检查，不是资源永久仓库。</p><p>Interactions Endpoint URL：</p><code style="overflow-wrap:anywhere">${escapeHtml(`${url.origin}/interactions`)}</code></body></html>`,
      )
    }

    return json({ error: 'not_found' }, { status: 404 })
  },
}
