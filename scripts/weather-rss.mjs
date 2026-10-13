import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import Parser from 'rss-parser';
import { pathToFileURL } from 'node:url';

const GEO_URL = 'https://geocoding-api.open-meteo.com/v1/search';
const WEATHER_URL = 'https://api.open-meteo.com/v1/forecast';
const WMO = new Map([
  [0, 'Clear sky'], [1, 'Mainly clear'], [2, 'Partly cloudy'], [3, 'Overcast'],
  [45, 'Fog'], [48, 'Rime fog'], [51, 'Light drizzle'], [53, 'Moderate drizzle'],
  [55, 'Dense drizzle'], [56, 'Light freezing drizzle'], [57, 'Dense freezing drizzle'],
  [61, 'Slight rain'], [63, 'Moderate rain'], [65, 'Heavy rain'],
  [66, 'Light freezing rain'], [67, 'Heavy freezing rain'], [71, 'Slight snow'],
  [73, 'Moderate snow'], [75, 'Heavy snow'], [77, 'Snow grains'],
  [80, 'Slight rain showers'], [81, 'Moderate rain showers'], [82, 'Violent rain showers'],
  [85, 'Slight snow showers'], [86, 'Heavy snow showers'], [95, 'Thunderstorm'],
  [96, 'Thunderstorm with slight hail'], [99, 'Thunderstorm with heavy hail'],
]);

export const weatherSchema = z.object({
  city: z.string().trim().min(2).max(120).regex(/^[^,\x00-\x1f]+$/)
    .describe('Required city name, e.g. London or Toronto; use separate region/country fields.'),
  provinceOrState: z.string().trim().min(1).max(120).regex(/^[^,\x00-\x1f]+$/).optional()
    .describe('Optional region name or abbreviation, e.g. Ontario or CA; omitted means no region restriction.'),
  country: z.string().trim().min(2).max(120).optional()
    .describe('Optional English country name or ISO alpha-2 code, e.g. Canada or US; omitted means worldwide lookup.'),
}).strict();

export const rssSchema = z.object({
  feedUrl: z.string().url().max(2048).refine(value => {
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
    } catch { return false; }
  }, 'Use an HTTP/HTTPS URL without embedded credentials.')
    .describe('Required HTTP/HTTPS RSS or Atom feed URL, e.g. https://example.com/feed.xml.'),
  maxResults: z.number().int().min(1).max(50).optional().default(5)
    .describe('Maximum latest matching entries to return; default 5, range 1–50.'),
  searchQuery: z.string().trim().min(1).max(300).optional()
    .describe('Optional case-insensitive literal text in titles or full summaries; omitted means no filtering.'),
}).strict();

const geoPayloadSchema = z.object({
  results: z.array(z.object({
    name: z.string(), latitude: z.number().finite().min(-90).max(90),
    longitude: z.number().finite().min(-180).max(180),
    admin1: z.string().optional(), country: z.string().optional(), country_code: z.string().optional(),
  })).default([]),
});
const metric = z.number().finite().nullable();
const code = z.number().int().nullable();
const weatherPayloadSchema = z.object({
  timezone: z.string(),
  current: z.object({time: z.string(), temperature_2m: metric,
    apparent_temperature: metric, weather_code: code, wind_speed_10m: metric}),
  daily: z.object({time: z.array(z.string()).length(3),
    temperature_2m_min: z.array(metric).length(3), temperature_2m_max: z.array(metric).length(3),
    weather_code: z.array(code).length(3)}),
});

class ToolFailure extends Error {}
const textResult = (text, isError = false) => ({content: [{type: 'text', text}], ...(isError ? {isError: true} : {})});
const normalize = value => value.normalize('NFKD').replace(/\p{M}/gu, '').toLocaleLowerCase('en').trim();
const condition = value => value === null ? 'Unavailable' : WMO.get(value) ?? `Unknown WMO code ${value}`;
const formatMetric = (value, unit) => value === null ? 'Unavailable' : `${value.toFixed(1)} ${unit}`;

// Native ICU data resolves English country names without an extra dependency.
const ISO_CODES = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ');
const regionNames = new Intl.DisplayNames(['en'], {type: 'region', fallback: 'code'});
function countryCode(value) {
  if (!value) return undefined;
  const aliases = new Map([['uk', 'GB'], ['usa', 'US'], ['united states of america', 'US']]);
  const alias = aliases.get(normalize(value));
  if (alias) return alias;
  if (/^[A-Za-z]{2}$/.test(value) && ISO_CODES.includes(value.toUpperCase())) return value.toUpperCase();
  for (const candidate of ISO_CODES) {
    if (normalize(regionNames.of(candidate)) === normalize(value)) return candidate;
  }
  throw new ToolFailure('Country not recognized. Use its ISO alpha-2 code or English name.');
}

/** Fetch bounded decoded bytes with a deadline covering headers and body. */
async function fetchText(url, {fetchImpl, label, byteLimit, timeoutMs}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetchImpl(url, {
      signal: controller.signal, redirect: 'follow',
      headers: {'User-Agent': 'weather-rss-mcp/1.0', Accept: 'application/json, application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5'},
    });
    if (!response.ok) throw new ToolFailure(`${label} returned HTTP ${response.status}.`);
    if (!response.body) throw new ToolFailure(`${label} returned an empty response.`);
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > byteLimit) throw new ToolFailure(`${label} exceeds the ${byteLimit}-byte response limit.`);
        chunks.push(Buffer.from(value));
      }
    } finally {
      // Cancel on an oversized/failed read; release the stream lock in all cases.
      try { await reader.cancel(); } catch { /* Preserve the original error. */ }
      reader.releaseLock();
    }
    const bytes = Buffer.concat(chunks, size);
    // Feeds occasionally specify an encoding other than UTF-8.
    const declaration = bytes.subarray(0, 256).toString('ascii').match(/<\?xml[^>]*encoding=["']([^"']+)["']/i)?.[1];
    const charset = declaration ?? response.headers.get('content-type')?.match(/charset=["']?([^\s;"']+)/i)?.[1] ?? 'utf-8';
    let text;
    try { text = new TextDecoder(charset).decode(bytes); }
    catch { throw new ToolFailure(`${label} uses an unsupported character encoding.`); }
    if (!text.trim()) throw new ToolFailure(`${label} returned an empty response.`);
    return {text, finalUrl: response.url || String(url)};
  } catch (error) {
    if (controller.signal.aborted) throw new ToolFailure(`${label} timed out after ${timeoutMs / 1000} seconds.`);
    if (error instanceof ToolFailure) throw error;
    // Avoid exposing credentials, query strings, or arbitrary response bodies.
    throw new ToolFailure(`${label} could not be reached or returned an invalid HTTP response.`);
  } finally {
    clearTimeout(timer);
    if (response?.body && !response.body.locked) {
      try { await response.body.cancel(); } catch { /* Already consumed. */ }
    }
  }
}

async function fetchJson(url, options) {
  const {text} = await fetchText(url, {...options, byteLimit: 256 * 1024});
  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error();
    if (data.error) throw new ToolFailure(`${options.label} rejected the request.`);
    return data;
  } catch (error) {
    if (error instanceof ToolFailure) throw error;
    throw new ToolFailure(`${options.label} returned malformed JSON.`);
  }
}

function plainText(value) {
  return String(value ?? '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&#(x[\da-f]+|\d+);/gi, (match, value) => {
      const point = /^x/i.test(value) ? parseInt(value.slice(1), 16) : Number(value);
      return point > 0 && point <= 0x10ffff && !(point >= 0xd800 && point <= 0xdfff) ? String.fromCodePoint(point) : match;
    })
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (_, name) => ({amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' '}[name.toLowerCase()]))
    .replace(/\s+/g, ' ').trim();
}
const clip = (text, length) => text.length > length ? text.slice(0, length - 1).trimEnd() + '…' : text;
function httpLink(value, base) {
  if (!value) return null;
  try { const url = new URL(value, base); return ['http:', 'https:'].includes(url.protocol) ? url.href : null; }
  catch { return null; }
}

/** Register on an existing McpServer. fetchImpl/timeoutMs support dependency injection in tests. */
export function registerWeatherRssTools(server, {fetchImpl = globalThis.fetch, timeoutMs = 20000} = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('Native fetch requires Node.js 18+.');
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) throw new TypeError('timeoutMs must be positive.');
  const options = {fetchImpl, timeoutMs};
  const parser = new Parser({xml2js: {async: true}});

  server.tool('get_weather',
    'Retrieve current city weather and a three-day forecast including today. Specify region/country for ambiguous names; not for historical weather.',
    weatherSchema.shape,
    async args => {
      try {
        const {city, provinceOrState, country} = weatherSchema.parse(args);
        const cc = countryCode(country);
        const geoUrl = new URL(GEO_URL);
        geoUrl.search = new URLSearchParams({name: provinceOrState ? `${city}, ${provinceOrState}` : city,
          count: '10', language: 'en', format: 'json', ...(cc ? {countryCode: cc} : {})}).toString();
        const payload = geoPayloadSchema.safeParse(await fetchJson(geoUrl, {...options, label:'Location lookup'}));
        if (!payload.success) throw new ToolFailure('Location lookup returned invalid location fields.');
        const candidates = payload.data.results.filter(loc => !cc || loc.country_code === cc);
        candidates.sort((a, b) => Number(normalize(a.name) !== normalize(city)) - Number(normalize(b.name) !== normalize(city)));
        if (!candidates.length) throw new ToolFailure('No location matched. Check the city, region, and country spelling.');
        const loc = candidates[0];
        const forecastUrl = new URL(WEATHER_URL);
        forecastUrl.search = new URLSearchParams({latitude:String(loc.latitude), longitude:String(loc.longitude),
          current:'temperature_2m,apparent_temperature,weather_code,wind_speed_10m',
          daily:'weather_code,temperature_2m_max,temperature_2m_min',
          temperature_unit:'celsius', wind_speed_unit:'kmh', timezone:'auto', forecast_days:'3'}).toString();
        const forecast = weatherPayloadSchema.safeParse(await fetchJson(forecastUrl, {...options, label:'Weather forecast'}));
        if (!forecast.success) throw new ToolFailure('Weather API returned missing, invalid, or incomplete three-day forecast data.');
        const {current, daily, timezone} = forecast.data;
        const matched = [loc.name, loc.admin1, loc.country].filter(Boolean).join(', ');
        const lines = [
          `Weather: ${matched}`, `Coordinates: ${loc.latitude}, ${loc.longitude}`,
          `Local time: ${current.time} (${timezone})`,
          `Conditions: ${condition(current.weather_code)} (WMO ${current.weather_code ?? 'unavailable'})`,
          `Temperature: ${formatMetric(current.temperature_2m, '°C')}; feels like ${formatMetric(current.apparent_temperature, '°C')}`,
          `Wind: ${formatMetric(current.wind_speed_10m, 'km/h')}`, '', 'Three-day forecast (includes today):',
          ...daily.time.map((date, i) => `${date}: ${condition(daily.weather_code[i])}; low ${formatMetric(daily.temperature_2m_min[i], '°C')}, high ${formatMetric(daily.temperature_2m_max[i], '°C')}`),
          '', 'Source: Open-Meteo (model-derived current conditions).',
        ];
        if (candidates.length > 1) lines.push('Multiple locations matched; first exact-name/relevance match used. Refine region/country if needed.');
        return textResult(lines.join('\n'));
      } catch (error) {
        return textResult(error instanceof ToolFailure ? error.message : error instanceof z.ZodError ? 'Invalid weather arguments. Check required fields, types, and bounds.' : 'Unable to process weather data.', true);
      }
    });

  server.tool('get_rss_feed',
    'Fetch RSS/Atom channel information and latest matching entries. Search titles and full summaries before limiting; not for full article extraction.',
    rssSchema.shape,
    async args => {
      try {
        const {feedUrl, maxResults, searchQuery} = rssSchema.parse(args);
        const {text:xml, finalUrl} = await fetchText(feedUrl, {...options, label:'RSS/Atom feed', byteLimit:2 * 1024 * 1024});
        let feed;
        try { feed = await parser.parseString(xml); }
        catch { throw new ToolFailure('The URL returned malformed XML or an unsupported RSS/Atom feed.'); }
        if (!Array.isArray(feed.items)) throw new ToolFailure('The feed has an invalid entry collection.');
        const needle = searchQuery?.toLocaleLowerCase('en');
        const entries = feed.items.map(item => {
          const title = plainText(item.title || 'Untitled');
          const summary = plainText(item.contentSnippet || item['content:encodedSnippet'] || item.summary || item.content || item['content:encoded'] || '');
          const date = item.isoDate || item.pubDate || item.updated || null;
          const timestamp = date ? Date.parse(date) : NaN;
          return {title, summary, date, link:httpLink(item.link, finalUrl), timestamp};
        }).filter(item => !needle || item.title.toLocaleLowerCase('en').includes(needle) || item.summary.toLocaleLowerCase('en').includes(needle));
        // Stable order: known publication dates newest first, undated entries last.
        entries.sort((a, b) => (Number.isFinite(b.timestamp) ? b.timestamp : -Infinity) - (Number.isFinite(a.timestamp) ? a.timestamp : -Infinity));
        const selected = entries.slice(0, maxResults).map(({title, summary, date, link}) => ({title:clip(title,500), date, summary:clip(summary,800), link}));
        const result = {feed:{title:clip(plainText(feed.title || 'Untitled feed'),500),
          link:httpLink(feed.link,finalUrl), description:clip(plainText(feed.description || ''),2000), url:finalUrl},
          totalEntries:feed.items.length, matchingEntries:entries.length, returnedEntries:selected.length, entries:selected};
        if (!feed.items.length) result.message = 'Valid feed with no entries.';
        else if (!entries.length) result.message = 'No entries matched searchQuery.';
        return textResult(JSON.stringify(result, null, 2));
      } catch (error) {
        return textResult(error instanceof ToolFailure ? error.message : error instanceof z.ZodError ? 'Invalid feed arguments. Use an HTTP/HTTPS URL and maxResults from 1 to 50.' : 'Unable to process feed data.', true);
      }
    });
  return server;
}

// Importing this module only exports registration; executing it starts stdio MCP.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = new McpServer({name:'weather-rss', version:'1.0.0'});
  registerWeatherRssTools(server);
  try { await server.connect(new StdioServerTransport()); }
  catch { console.error('Unable to start weather/RSS MCP server.'); process.exitCode = 1; }
}
