#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  TOKEN_FILE,
  tokenExists,
  loadToken,
  googleFetch,
  safeWorkspace,
  clipText,
  base64UrlEncode,
  base64UrlDecode,
  quoteDriveLiteral,
} from './google-common.mjs';
import { decorateCatalogTools, SERVER_CATALOG } from './catalog-metadata.mjs';

const MAX_OUTPUT = Number(process.env.GOOGLE_TOOLS_MAX_OUTPUT || 65536);
const GMAIL_WRITE = /^(1|true|yes)$/i.test(process.env.GOOGLE_GMAIL_WRITE || 'false');
const CALENDAR_WRITE = /^(1|true|yes)$/i.test(process.env.GOOGLE_CALENDAR_WRITE || 'false');
const DRIVE_WRITE = /^(1|true|yes)$/i.test(process.env.GOOGLE_DRIVE_WRITE || 'false');

const s = (description, properties = {}, required = []) => ({ type: 'object', description, properties, required, additionalProperties: false });
const str = (description, extra = {}) => ({ type: 'string', description, ...extra });
const num = (description, extra = {}) => ({ type: 'number', description, ...extra });
const bool = (description) => ({ type: 'boolean', description });
const arr = (description, items) => ({ type: 'array', description, items });

const TOOLS = [
  {
    name: 'google_auth_status',
    description: 'Google account authorization status: report whether OAuth credentials are configured, whether an encrypted user token exists, granted scopes, token expiry, and enabled write gates. Use for Google/Gmail/Calendar/Drive authentication troubleshooting. Never returns secrets or token values.',
    inputSchema: s('Check local Google Workspace OAuth status. No credentials are accepted as arguments.', {}),
  },

  // Gmail
  {
    name: 'gmail_get_unread_count',
    description: 'Gmail unread count: return the exact unread message and unread thread counts for a Gmail label, default INBOX. Use for scalar questions such as "how many unread emails do I have?", "unread inbox count", or "number of unread Gmail messages". Prefer this over gmail_search_messages when only a count is needed.',
    inputSchema: s('Get exact Gmail unread counts from one label without listing messages.', {
      label_id: str('Gmail label ID to count; default "INBOX". Common system IDs include INBOX, UNREAD, SPAM, TRASH, SENT, and STARRED.'),
    }),
  },
  {
    name: 'gmail_search_messages',
    description: 'Gmail search: list messages in the authorized mailbox using normal Gmail search syntax such as from:, to:, subject:, newer_than:, label:, has:attachment, is:unread, or free text. Returns message IDs, thread IDs, headers, labels, dates, and snippets. Use when the user needs matching messages or message details. Do not use it only to count unread mail; use gmail_get_unread_count instead because search result_size_estimate is not an exact count.',
    inputSchema: s('Search and list Gmail messages with Gmail query syntax; not for exact mailbox counts.', {
      query: str('Gmail search query, e.g. "in:inbox is:unread newer_than:7d", "from:alice@example.com", or "subject:invoice".'),
      max_results: num('Maximum messages to return; default 20, maximum 100.', { minimum: 1, maximum: 100 }),
      page_token: str('Optional Gmail page token for continuing a previous search.'),
    }),
  },
  {
    name: 'gmail_get_message',
    description: 'Gmail read message: fetch one message by Gmail message ID with From/To/Cc/Subject/Date headers, labels, snippet, and decoded text body when available. Use after gmail_search_messages when the full email content is needed.',
    inputSchema: s('Read one Gmail message.', {
      message_id: str('Gmail message ID returned by Gmail search or thread tools.'),
      include_body: bool('Include decoded text body; default true.'),
    }, ['message_id']),
  },
  {
    name: 'gmail_get_thread',
    description: 'Gmail read thread: fetch all messages in one conversation thread in chronological API order, including headers, labels, snippets, and decoded text bodies. Use to understand an email conversation or recover reply context.',
    inputSchema: s('Read one Gmail conversation thread.', {
      thread_id: str('Gmail thread ID.'),
      include_body: bool('Include decoded text bodies; default true.'),
    }, ['thread_id']),
  },
  {
    name: 'gmail_list_labels',
    description: 'Gmail labels: list system and user labels with IDs and names. Use to discover label IDs before filtering or modifying labels, or to inspect mailbox organization.',
    inputSchema: s('List Gmail labels.', {}),
  },
  {
    name: 'gmail_create_draft',
    description: 'Gmail create draft: create an unsent email draft in the authorized mailbox. Supports To/Cc/Bcc, subject, plain-text body, and optional thread/reply headers. Mutating tool; disabled unless GOOGLE_GMAIL_WRITE=true and OAuth includes a Gmail write/compose scope.',
    inputSchema: s('Create an unsent Gmail draft.', {
      to: arr('Recipient email addresses.', str('Email address.')),
      subject: str('Email subject.'),
      body: str('Plain-text email body.'),
      cc: arr('Optional CC recipients.', str('Email address.')),
      bcc: arr('Optional BCC recipients.', str('Email address.')),
      thread_id: str('Optional Gmail thread ID to associate this draft with a conversation.'),
      in_reply_to: str('Optional RFC Message-ID value for In-Reply-To when creating a reply.'),
      references: str('Optional RFC References header value when creating a reply.'),
    }, ['to', 'subject', 'body']),
  },
  {
    name: 'gmail_send_draft',
    description: 'Gmail send draft: send an existing Gmail draft by draft ID. Use only after the draft has been created/reviewed. Mutating tool; disabled unless GOOGLE_GMAIL_WRITE=true and OAuth includes a Gmail send/modify scope.',
    inputSchema: s('Send an existing Gmail draft.', { draft_id: str('Gmail draft ID.') }, ['draft_id']),
  },
  {
    name: 'gmail_modify_labels',
    description: 'Gmail modify message labels: add or remove Gmail label IDs on one message. Common actions include archive (remove INBOX), mark read (remove UNREAD), mark unread (add UNREAD), star (add STARRED), or apply a user label. Mutating tool; disabled unless GOOGLE_GMAIL_WRITE=true.',
    inputSchema: s('Add/remove labels on one Gmail message.', {
      message_id: str('Gmail message ID.'),
      add_label_ids: arr('Label IDs to add.', str('Gmail label ID.')),
      remove_label_ids: arr('Label IDs to remove.', str('Gmail label ID.')),
    }, ['message_id']),
  },

  // Calendar
  {
    name: 'calendar_list_calendars',
    description: 'Google Calendar list calendars: return calendars visible to the authorized account with IDs, names, access roles, primary flag, and time zones. Use to discover calendar IDs before reading events or availability.',
    inputSchema: s('List calendars visible to the account.', {
      max_results: num('Maximum calendars; default 100, maximum 250.', { minimum: 1, maximum: 250 }),
      page_token: str('Optional continuation token.'),
    }),
  },
  {
    name: 'calendar_list_events',
    description: 'Google Calendar events: list events from a calendar over a time range, optionally filtered by text query. Returns event IDs, summaries, start/end, location, attendees, organizer, status, and links. Use for schedule lookup, upcoming meetings, agenda, appointments, or finding an event before updating it.',
    inputSchema: s('List events from one Google Calendar.', {
      calendar_id: str('Calendar ID; default "primary".'),
      time_min: str('RFC3339 lower bound, e.g. 2026-09-30T00:00:00-04:00.'),
      time_max: str('RFC3339 upper bound.'),
      query: str('Optional free-text Calendar search query.'),
      max_results: num('Maximum events; default 50, maximum 250.', { minimum: 1, maximum: 250 }),
      page_token: str('Optional continuation token.'),
    }),
  },
  {
    name: 'calendar_get_event',
    description: 'Google Calendar read event: fetch complete details for one event by calendar ID and event ID, including times, attendees, conferencing, recurrence, reminders, description, and organizer.',
    inputSchema: s('Read one Google Calendar event.', {
      calendar_id: str('Calendar ID; default "primary".'),
      event_id: str('Google Calendar event ID.'),
    }, ['event_id']),
  },
  {
    name: 'calendar_freebusy',
    description: 'Google Calendar free/busy: check busy time blocks for one or more calendars between two RFC3339 timestamps. Use for availability, scheduling, conflict checks, and finding meeting windows without loading full event details.',
    inputSchema: s('Check Google Calendar availability.', {
      time_min: str('RFC3339 start timestamp.'),
      time_max: str('RFC3339 end timestamp.'),
      calendar_ids: arr('Calendar IDs; use "primary" for the main calendar.', str('Calendar ID.')),
      time_zone: str('Optional IANA time zone such as America/Toronto.'),
    }, ['time_min', 'time_max', 'calendar_ids']),
  },
  {
    name: 'calendar_create_event',
    description: 'Google Calendar create event: add an event with summary, start/end, description, location, attendees, and optional time zone. Supports timed or all-day events. Mutating tool; disabled unless GOOGLE_CALENDAR_WRITE=true and OAuth includes a Calendar event-write scope.',
    inputSchema: s('Create a Google Calendar event.', {
      calendar_id: str('Calendar ID; default "primary".'),
      summary: str('Event title.'),
      start: str('RFC3339 timestamp for timed events, or YYYY-MM-DD for all-day events.'),
      end: str('RFC3339 timestamp for timed events, or exclusive YYYY-MM-DD end date for all-day events.'),
      all_day: bool('Treat start/end as YYYY-MM-DD all-day dates.'),
      time_zone: str('IANA time zone for timed events, e.g. America/Toronto.'),
      description: str('Optional event description.'),
      location: str('Optional location.'),
      attendees: arr('Optional attendee email addresses.', str('Email address.')),
    }, ['summary', 'start', 'end']),
  },
  {
    name: 'calendar_update_event',
    description: 'Google Calendar update event: patch selected fields on an existing event, such as title, times, location, description, or attendees. Mutating tool; disabled unless GOOGLE_CALENDAR_WRITE=true.',
    inputSchema: s('Patch an existing Google Calendar event.', {
      calendar_id: str('Calendar ID; default "primary".'),
      event_id: str('Google Calendar event ID.'),
      summary: str('New event title.'),
      start: str('New RFC3339 timestamp or YYYY-MM-DD date.'),
      end: str('New RFC3339 timestamp or YYYY-MM-DD date.'),
      all_day: bool('Treat supplied start/end as all-day dates.'),
      time_zone: str('IANA time zone for timed event values.'),
      description: str('New description.'),
      location: str('New location.'),
      attendees: arr('Replacement attendee email addresses.', str('Email address.')),
    }, ['event_id']),
  },
  {
    name: 'calendar_delete_event',
    description: 'Google Calendar delete event: permanently delete one event by calendar ID and event ID. Mutating/destructive tool; disabled unless GOOGLE_CALENDAR_WRITE=true.',
    inputSchema: s('Delete one Google Calendar event.', {
      calendar_id: str('Calendar ID; default "primary".'),
      event_id: str('Google Calendar event ID.'),
    }, ['event_id']),
  },

  // Drive
  {
    name: 'drive_search_files',
    description: 'Google Drive search: find files and folders across Drive by plain text, name substring, MIME type, parent folder, or raw Drive v3 q expression. Returns IDs, names, MIME types, modified times, sizes, parents, owners, and web links. Use for locating Docs/Sheets/Slides/PDFs or files before reading/downloading them.',
    inputSchema: s('Search Google Drive files/folders.', {
      text: str('Plain-text term searched with Drive fullText contains.'),
      name_contains: str('Optional filename substring.'),
      mime_type: str('Optional exact Drive MIME type.'),
      parent_id: str('Optional parent folder ID.'),
      query: str('Optional raw Drive v3 q expression. Combined with the simpler filters when supplied.'),
      include_trashed: bool('Include trashed files; default false.'),
      max_results: num('Maximum files; default 50, maximum 200.', { minimum: 1, maximum: 200 }),
      page_token: str('Optional continuation token.'),
    }),
  },
  {
    name: 'drive_get_file_metadata',
    description: 'Google Drive file metadata: fetch details for one Drive file/folder by ID, including name, MIME type, size, parents, owners, timestamps, capabilities, shortcut details, and web links. Use after Drive search when exact file identity or type matters.',
    inputSchema: s('Read metadata for one Drive item.', { file_id: str('Google Drive file ID.') }, ['file_id']),
  },
  {
    name: 'drive_read_text',
    description: 'Google Drive read text: read textual content from a Drive file. Native Google Docs are exported as text/plain, Sheets as CSV, Slides as text/plain when supported; ordinary text/JSON/XML/CSV/Markdown files are downloaded directly. Use for document content without first saving a local copy. For binary/large files use drive_download_file.',
    inputSchema: s('Read text content from one Google Drive file.', {
      file_id: str('Google Drive file ID.'),
      max_chars: num('Maximum returned characters; default 60000, maximum 200000.', { minimum: 100, maximum: 200000 }),
    }, ['file_id']),
  },
  {
    name: 'drive_download_file',
    description: 'Google Drive download/export: save one Drive file into the shared MCP workspace for later document/image processing. Native Google Workspace files require or infer an export MIME type; ordinary files are downloaded as-is. Returns only the workspace path, not credentials or binary content.',
    inputSchema: s('Download or export a Drive file into MCP_WORKSPACE.', {
      file_id: str('Google Drive file ID.'),
      output: str('Workspace-relative output path, e.g. "downloads/report.pdf".'),
      export_mime_type: str('Optional export MIME type for Google Docs/Sheets/Slides, e.g. application/pdf, text/plain, text/csv, or application/vnd.openxmlformats-officedocument.wordprocessingml.document.'),
    }, ['file_id', 'output']),
  },
  {
    name: 'drive_create_folder',
    description: 'Google Drive create folder: create a new Drive folder, optionally inside a parent folder. Mutating tool; disabled unless GOOGLE_DRIVE_WRITE=true and OAuth includes a Drive write scope.',
    inputSchema: s('Create a Google Drive folder.', {
      name: str('Folder name.'),
      parent_id: str('Optional parent folder ID.'),
    }, ['name']),
  },
  {
    name: 'drive_upload_file',
    description: 'Google Drive upload file: upload one existing file from the shared MCP workspace to Drive, optionally into a parent folder. Mutating tool; disabled unless GOOGLE_DRIVE_WRITE=true. The tool accepts a workspace path, never local credentials.',
    inputSchema: s('Upload a workspace file to Google Drive.', {
      path: str('Workspace-relative source path.'),
      name: str('Optional destination filename; defaults to source basename.'),
      mime_type: str('Content MIME type, e.g. text/plain, application/pdf, image/png, application/zip.'),
      parent_id: str('Optional destination folder ID.'),
    }, ['path', 'mime_type']),
  },
  {
    name: 'drive_delete_file',
    description: 'Google Drive delete file: permanently delete one Drive file/folder by ID. Mutating/destructive tool; disabled unless GOOGLE_DRIVE_WRITE=true.',
    inputSchema: s('Delete one Google Drive file or folder.', { file_id: str('Google Drive file ID.') }, ['file_id']),
  },
];


const GOOGLE_MUTATING = new Set([
  'gmail_create_draft','gmail_send_draft','gmail_modify_labels',
  'calendar_create_event','calendar_update_event','calendar_delete_event',
  'drive_create_folder','drive_upload_file','drive_delete_file',
]);
const GOOGLE_DESTRUCTIVE = new Set(['calendar_delete_event','drive_delete_file']);
for (const tool of TOOLS) {
  const mutating = GOOGLE_MUTATING.has(tool.name);
  tool.annotations = {
    readOnlyHint: !mutating,
    destructiveHint: GOOGLE_DESTRUCTIVE.has(tool.name),
    idempotentHint: !mutating,
    openWorldHint: true,
  };
}

const CATALOG_TOOLS = decorateCatalogTools(TOOLS, 'google');
const toolMap = new Map(TOOLS.map(t => [t.name, t]));

function requireGate(enabled, name, envName) {
  if (!enabled) throw new Error(`${name} is disabled; set ${envName}=true and authorize an OAuth write scope to enable it`);
}

function qs(params = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) for (const item of v) p.append(k, String(item));
    else p.set(k, String(v));
  }
  return p.toString();
}

function headerMap(headers = []) {
  const out = {};
  for (const h of headers) if (h?.name) out[h.name.toLowerCase()] = h.value || '';
  return out;
}

function extractGmailBody(payload) {
  if (!payload) return '';
  const found = [];
  const walk = part => {
    if (!part) return;
    if (part.mimeType === 'text/plain' && part.body?.data) found.push(base64UrlDecode(part.body.data));
    for (const child of part.parts || []) walk(child);
  };
  walk(payload);
  if (found.length) return found.join('\n\n').trim();
  if (payload.body?.data) return base64UrlDecode(payload.body.data).trim();
  return '';
}

function normalizeMessage(m, includeBody = true) {
  const h = headerMap(m.payload?.headers || []);
  return {
    id: m.id,
    thread_id: m.threadId,
    label_ids: m.labelIds || [],
    internal_date: m.internalDate ? new Date(Number(m.internalDate)).toISOString() : undefined,
    from: h.from,
    to: h.to,
    cc: h.cc,
    subject: h.subject,
    date: h.date,
    message_id_header: h['message-id'],
    references: h.references,
    in_reply_to: h['in-reply-to'],
    snippet: m.snippet,
    ...(includeBody ? { body: extractGmailBody(m.payload) } : {}),
  };
}

function sanitizeHeader(value) {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim();
}

function buildRawMail(a) {
  const lines = [];
  lines.push(`To: ${(a.to || []).map(sanitizeHeader).join(', ')}`);
  if (a.cc?.length) lines.push(`Cc: ${a.cc.map(sanitizeHeader).join(', ')}`);
  if (a.bcc?.length) lines.push(`Bcc: ${a.bcc.map(sanitizeHeader).join(', ')}`);
  lines.push(`Subject: ${sanitizeHeader(a.subject)}`);
  if (a.in_reply_to) lines.push(`In-Reply-To: ${sanitizeHeader(a.in_reply_to)}`);
  if (a.references) lines.push(`References: ${sanitizeHeader(a.references)}`);
  lines.push('MIME-Version: 1.0');
  lines.push('Content-Type: text/plain; charset=UTF-8');
  lines.push('Content-Transfer-Encoding: 8bit');
  lines.push('');
  lines.push(String(a.body || ''));
  return lines.join('\r\n');
}

function eventTime(value, allDay, timeZone) {
  if (allDay) return value === undefined ? undefined : { date: value };
  if (value === undefined) return undefined;
  return { dateTime: value, ...(timeZone ? { timeZone } : {}) };
}

async function fileMeta(fileId) {
  const fields = 'id,name,mimeType,size,parents,modifiedTime,createdTime,webViewLink,webContentLink,owners(displayName,emailAddress),capabilities,shortcutDetails,trashed';
  const { body } = await googleFetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?${qs({ fields, supportsAllDrives: true })}`);
  return body;
}

function defaultExportMime(meta, output = '') {
  const ext = path.extname(output).toLowerCase();
  if (ext === '.pdf') return 'application/pdf';
  if (meta.mimeType === 'application/vnd.google-apps.document') {
    if (ext === '.docx') return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    if (ext === '.html') return 'text/html';
    return 'text/plain';
  }
  if (meta.mimeType === 'application/vnd.google-apps.spreadsheet') {
    if (ext === '.xlsx') return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    return 'text/csv';
  }
  if (meta.mimeType === 'application/vnd.google-apps.presentation') {
    if (ext === '.pptx') return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
    if (ext === '.txt') return 'text/plain';
    return 'application/pdf';
  }
  return null;
}

async function callTool(name, a) {
  switch (name) {
    case 'google_auth_status': {
      const exists = tokenExists();
      let token = null;
      let tokenError = null;
      if (exists) {
        try { token = await loadToken(); } catch (e) { tokenError = e?.message || String(e); }
      }
      return {
        authorized: Boolean(token?.refresh_token || token?.access_token),
        token_file_present: exists,
        token_file: TOKEN_FILE,
        token_read_error: tokenError,
        granted_scopes: String(token?.scope || '').split(/\s+/).filter(Boolean),
        access_token_expiry: token?.expiry_date ? new Date(Number(token.expiry_date)).toISOString() : null,
        has_refresh_token: Boolean(token?.refresh_token),
        write_gates: { gmail: GMAIL_WRITE, calendar: CALENDAR_WRITE, drive: DRIVE_WRITE },
      };
    }

    case 'gmail_get_unread_count': {
      const labelId = String(a.label_id || 'INBOX').trim() || 'INBOX';
      const { body } = await googleFetch(`https://gmail.googleapis.com/gmail/v1/users/me/labels/${encodeURIComponent(labelId)}`);
      return {
        label_id: body.id || labelId,
        label_name: body.name || labelId,
        messages_unread: Number(body.messagesUnread || 0),
        threads_unread: Number(body.threadsUnread || 0),
      };
    }
    case 'gmail_search_messages': {
      const max = Math.max(1, Math.min(100, Number(a.max_results || 20)));
      const u = `https://gmail.googleapis.com/gmail/v1/users/me/messages?${qs({ q: a.query, maxResults: max, pageToken: a.page_token })}`;
      const { body } = await googleFetch(u);
      const ids = (body.messages || []).slice(0, max);
      const messages = await Promise.all(ids.map(async ({ id }) => {
        const p = new URLSearchParams({ format: 'metadata' });
        for (const h of ['From', 'To', 'Cc', 'Subject', 'Date', 'Message-ID']) p.append('metadataHeaders', h);
        const r = await googleFetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}?${p}`);
        return normalizeMessage(r.body, false);
      }));
      return { messages, next_page_token: body.nextPageToken || null, result_size_estimate: body.resultSizeEstimate };
    }
    case 'gmail_get_message': {
      const { body } = await googleFetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(a.message_id)}?format=full`);
      return normalizeMessage(body, a.include_body !== false);
    }
    case 'gmail_get_thread': {
      const { body } = await googleFetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads/${encodeURIComponent(a.thread_id)}?format=full`);
      return { id: body.id, history_id: body.historyId, messages: (body.messages || []).map(m => normalizeMessage(m, a.include_body !== false)) };
    }
    case 'gmail_list_labels': {
      const { body } = await googleFetch('https://gmail.googleapis.com/gmail/v1/users/me/labels');
      return body.labels || [];
    }
    case 'gmail_create_draft': {
      requireGate(GMAIL_WRITE, 'Gmail writes', 'GOOGLE_GMAIL_WRITE');
      const payload = { message: { raw: base64UrlEncode(buildRawMail(a)), ...(a.thread_id ? { threadId: a.thread_id } : {}) } };
      const { body } = await googleFetch('https://gmail.googleapis.com/gmail/v1/users/me/drafts', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
      });
      return { id: body.id, message_id: body.message?.id, thread_id: body.message?.threadId };
    }
    case 'gmail_send_draft': {
      requireGate(GMAIL_WRITE, 'Gmail writes', 'GOOGLE_GMAIL_WRITE');
      const { body } = await googleFetch('https://gmail.googleapis.com/gmail/v1/users/me/drafts/send', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: a.draft_id }),
      });
      return { id: body.id, thread_id: body.threadId, label_ids: body.labelIds };
    }
    case 'gmail_modify_labels': {
      requireGate(GMAIL_WRITE, 'Gmail writes', 'GOOGLE_GMAIL_WRITE');
      const { body } = await googleFetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(a.message_id)}/modify`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ addLabelIds: a.add_label_ids || [], removeLabelIds: a.remove_label_ids || [] }),
      });
      return { id: body.id, thread_id: body.threadId, label_ids: body.labelIds };
    }

    case 'calendar_list_calendars': {
      const { body } = await googleFetch(`https://www.googleapis.com/calendar/v3/users/me/calendarList?${qs({ maxResults: Math.max(1, Math.min(250, Number(a.max_results || 100))), pageToken: a.page_token })}`);
      return { calendars: body.items || [], next_page_token: body.nextPageToken || null };
    }
    case 'calendar_list_events': {
      const params = {
        timeMin: a.time_min, timeMax: a.time_max, q: a.query,
        maxResults: Math.max(1, Math.min(250, Number(a.max_results || 50))), pageToken: a.page_token,
        singleEvents: true, orderBy: 'startTime',
      };
      const { body } = await googleFetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(a.calendar_id || 'primary')}/events?${qs(params)}`);
      return { time_zone: body.timeZone, events: body.items || [], next_page_token: body.nextPageToken || null };
    }
    case 'calendar_get_event': {
      const { body } = await googleFetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(a.calendar_id || 'primary')}/events/${encodeURIComponent(a.event_id)}`);
      return body;
    }
    case 'calendar_freebusy': {
      const { body } = await googleFetch('https://www.googleapis.com/calendar/v3/freeBusy', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
          timeMin: a.time_min, timeMax: a.time_max, timeZone: a.time_zone,
          items: (a.calendar_ids || []).map(id => ({ id })),
        }),
      });
      return body;
    }
    case 'calendar_create_event': {
      requireGate(CALENDAR_WRITE, 'Calendar writes', 'GOOGLE_CALENDAR_WRITE');
      const event = {
        summary: a.summary, start: eventTime(a.start, !!a.all_day, a.time_zone), end: eventTime(a.end, !!a.all_day, a.time_zone),
        ...(a.description !== undefined ? { description: a.description } : {}),
        ...(a.location !== undefined ? { location: a.location } : {}),
        ...(a.attendees ? { attendees: a.attendees.map(email => ({ email })) } : {}),
      };
      const { body } = await googleFetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(a.calendar_id || 'primary')}/events?sendUpdates=all`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(event),
      });
      return body;
    }
    case 'calendar_update_event': {
      requireGate(CALENDAR_WRITE, 'Calendar writes', 'GOOGLE_CALENDAR_WRITE');
      const patch = {};
      for (const k of ['summary', 'description', 'location']) if (a[k] !== undefined) patch[k] = a[k];
      if (a.start !== undefined) patch.start = eventTime(a.start, !!a.all_day, a.time_zone);
      if (a.end !== undefined) patch.end = eventTime(a.end, !!a.all_day, a.time_zone);
      if (a.attendees !== undefined) patch.attendees = a.attendees.map(email => ({ email }));
      const { body } = await googleFetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(a.calendar_id || 'primary')}/events/${encodeURIComponent(a.event_id)}?sendUpdates=all`, {
        method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(patch),
      });
      return body;
    }
    case 'calendar_delete_event': {
      requireGate(CALENDAR_WRITE, 'Calendar writes', 'GOOGLE_CALENDAR_WRITE');
      await googleFetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(a.calendar_id || 'primary')}/events/${encodeURIComponent(a.event_id)}?sendUpdates=all`, { method: 'DELETE' });
      return { ok: true, calendar_id: a.calendar_id || 'primary', event_id: a.event_id };
    }

    case 'drive_search_files': {
      const filters = [];
      if (a.text) filters.push(`fullText contains '${quoteDriveLiteral(a.text)}'`);
      if (a.name_contains) filters.push(`name contains '${quoteDriveLiteral(a.name_contains)}'`);
      if (a.mime_type) filters.push(`mimeType = '${quoteDriveLiteral(a.mime_type)}'`);
      if (a.parent_id) filters.push(`'${quoteDriveLiteral(a.parent_id)}' in parents`);
      if (!a.include_trashed) filters.push('trashed = false');
      if (a.query) filters.push(`(${a.query})`);
      const fields = 'nextPageToken,files(id,name,mimeType,size,parents,modifiedTime,createdTime,webViewLink,webContentLink,owners(displayName,emailAddress),trashed)';
      const { body } = await googleFetch(`https://www.googleapis.com/drive/v3/files?${qs({
        q: filters.join(' and '), fields, pageSize: Math.max(1, Math.min(200, Number(a.max_results || 50))), pageToken: a.page_token,
        spaces: 'drive', corpora: 'user', includeItemsFromAllDrives: true, supportsAllDrives: true,
      })}`);
      return { files: body.files || [], next_page_token: body.nextPageToken || null };
    }
    case 'drive_get_file_metadata': return fileMeta(a.file_id);
    case 'drive_read_text': {
      const meta = await fileMeta(a.file_id);
      const max = Math.max(100, Math.min(200000, Number(a.max_chars || 60000)));
      let url;
      if (meta.mimeType?.startsWith('application/vnd.google-apps.')) {
        const mime = defaultExportMime(meta, meta.mimeType === 'application/vnd.google-apps.spreadsheet' ? '.csv' : '.txt');
        if (!mime || mime === 'application/pdf') throw new Error(`Drive item ${meta.name} (${meta.mimeType}) cannot be safely returned as text; use drive_download_file with an explicit export format`);
        url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(a.file_id)}/export?${qs({ mimeType: mime })}`;
      } else {
        const textual = meta.mimeType?.startsWith('text/') || ['application/json','application/xml','application/yaml','application/x-yaml','application/javascript'].includes(meta.mimeType);
        if (!textual) throw new Error(`Drive item ${meta.name} (${meta.mimeType}) is not a text file; use drive_download_file then the appropriate document/image tool`);
        url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(a.file_id)}?alt=media&supportsAllDrives=true`;
      }
      const { body } = await googleFetch(url);
      const text = Buffer.isBuffer(body) ? body.toString('utf8') : JSON.stringify(body, null, 2);
      return { id: meta.id, name: meta.name, mime_type: meta.mimeType, text: clipText(text, max) };
    }
    case 'drive_download_file': {
      const meta = await fileMeta(a.file_id);
      const output = safeWorkspace(a.output);
      await fsp.mkdir(path.dirname(output), { recursive: true });
      let mime = a.export_mime_type;
      let url;
      if (meta.mimeType?.startsWith('application/vnd.google-apps.')) {
        mime ||= defaultExportMime(meta, a.output);
        if (!mime) throw new Error(`export_mime_type is required for ${meta.mimeType}`);
        url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(a.file_id)}/export?${qs({ mimeType: mime })}`;
      } else {
        const textual = meta.mimeType?.startsWith('text/') || ['application/json','application/xml','application/yaml','application/x-yaml','application/javascript'].includes(meta.mimeType);
        if (!textual) throw new Error(`Drive item ${meta.name} (${meta.mimeType}) is not a text file; use drive_download_file then the appropriate document/image tool`);
        url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(a.file_id)}?alt=media&supportsAllDrives=true`;
      }
      const { body } = await googleFetch(url);
      const data = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
      await fsp.writeFile(output, data);
      return { ok: true, file_id: a.file_id, source_name: meta.name, source_mime_type: meta.mimeType, export_mime_type: mime || null, output: path.relative(path.resolve(process.env.MCP_WORKSPACE || '/workspace'), output), bytes: data.length };
    }
    case 'drive_create_folder': {
      requireGate(DRIVE_WRITE, 'Drive writes', 'GOOGLE_DRIVE_WRITE');
      const metadata = { name: a.name, mimeType: 'application/vnd.google-apps.folder', ...(a.parent_id ? { parents: [a.parent_id] } : {}) };
      const { body } = await googleFetch(`https://www.googleapis.com/drive/v3/files?${qs({ fields: 'id,name,mimeType,parents,webViewLink', supportsAllDrives: true })}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(metadata),
      });
      return body;
    }
    case 'drive_upload_file': {
      requireGate(DRIVE_WRITE, 'Drive writes', 'GOOGLE_DRIVE_WRITE');
      const src = safeWorkspace(a.path, { mustExist: true });
      const st = await fsp.stat(src);
      if (!st.isFile()) throw new Error('drive_upload_file source must be a regular file');
      const data = await fsp.readFile(src);
      const boundary = `mcp-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const metadata = { name: a.name || path.basename(src), ...(a.parent_id ? { parents: [a.parent_id] } : {}) };
      const prefix = Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: ${a.mime_type}\r\n\r\n`);
      const suffix = Buffer.from(`\r\n--${boundary}--\r\n`);
      const { body } = await googleFetch(`https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&${qs({ fields: 'id,name,mimeType,size,parents,webViewLink', supportsAllDrives: true })}`, {
        method: 'POST', headers: { 'content-type': `multipart/related; boundary=${boundary}` }, body: Buffer.concat([prefix, data, suffix]),
      });
      return body;
    }
    case 'drive_delete_file': {
      requireGate(DRIVE_WRITE, 'Drive writes', 'GOOGLE_DRIVE_WRITE');
      await googleFetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(a.file_id)}?supportsAllDrives=true`, { method: 'DELETE' });
      return { ok: true, file_id: a.file_id };
    }
  }
  throw new Error(`unknown tool: ${name}`);
}

function response(id, result) { process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result })}\n`); }
function errorResponse(id, code, message, data) { process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } })}\n`); }

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  input += chunk;
  let idx;
  while ((idx = input.indexOf('\n')) >= 0) {
    const line = input.slice(0, idx).trim();
    input = input.slice(idx + 1);
    if (line) handle(line);
  }
});

async function handle(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') return;
  if (msg.id == null) return;
  try {
    if (msg.method === 'initialize') return response(msg.id, { protocolVersion: msg.params?.protocolVersion || '2025-06-18', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'local-google-workspace-tools', version: '1.0.0' }, instructions: SERVER_CATALOG.google.description });
    if (msg.method === 'ping') return response(msg.id, {});
    if (msg.method === 'tools/list') return response(msg.id, { tools: CATALOG_TOOLS });
    if (msg.method === 'tools/call') {
      const name = msg.params?.name;
      const args = msg.params?.arguments || {};
      if (!toolMap.has(name)) throw new Error(`unknown tool: ${name}`);
      try {
        const out = await callTool(name, args);
        return response(msg.id, { content: [{ type: 'text', text: clipText(out, MAX_OUTPUT) }], isError: false });
      } catch (e) {
        return response(msg.id, { content: [{ type: 'text', text: clipText(e?.stack || String(e), MAX_OUTPUT) }], isError: true });
      }
    }
    return errorResponse(msg.id, -32601, `Method not found: ${msg.method}`);
  } catch (e) {
    return errorResponse(msg.id, -32603, e?.message || String(e));
  }
}
