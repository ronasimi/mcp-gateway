const WEATHER_URL = new URL('https://api.open-meteo.com/v1/forecast');
WEATHER_URL.searchParams.set('latitude', '42.98');
WEATHER_URL.searchParams.set('longitude', '-81.23');
WEATHER_URL.searchParams.set('current', 'temperature_2m,weather_code,is_day');
WEATHER_URL.searchParams.set('daily', 'weather_code,temperature_2m_max,temperature_2m_min');
WEATHER_URL.searchParams.set('temperature_unit', 'celsius');
WEATHER_URL.searchParams.set('timezone', 'America/Toronto');
WEATHER_URL.searchParams.set('forecast_days', '7');

export const CBC_LONDON_RSS_URL = 'https://www.cbc.ca/webfeed/rss/rss-canada-london';
export const OPEN_METEO_LONDON_URL = WEATHER_URL.toString();

const REQUEST_TIMEOUT_MS = 12_000;
const DESCRIPTION_LIMIT = 240;

export function wmoCondition(code, isDay = true) {
  const n = Number(code);
  if (n === 0) return { emoji: isDay ? '☀️' : '🌙', label: 'Clear sky' };
  if (n === 1) return { emoji: isDay ? '🌤️' : '🌙', label: 'Mainly clear' };
  if (n === 2) return { emoji: '⛅', label: 'Partly cloudy' };
  if (n === 3) return { emoji: '☁️', label: 'Overcast' };
  if ([45, 48].includes(n)) return { emoji: '🌫️', label: n === 48 ? 'Rime fog' : 'Fog' };
  if ([51, 53, 55].includes(n)) return { emoji: '🌦️', label: 'Drizzle' };
  if ([56, 57].includes(n)) return { emoji: '🧊', label: 'Freezing drizzle' };
  if ([61, 63, 65].includes(n)) return { emoji: '🌧️', label: 'Rain' };
  if ([66, 67].includes(n)) return { emoji: '🌧️', label: 'Freezing rain' };
  if ([71, 73, 75, 77].includes(n)) return { emoji: '❄️', label: n === 77 ? 'Snow grains' : 'Snow' };
  if ([80, 81, 82].includes(n)) return { emoji: '🌦️', label: 'Rain showers' };
  if ([85, 86].includes(n)) return { emoji: '🌨️', label: 'Snow showers' };
  if (n === 95) return { emoji: '⛈️', label: 'Thunderstorm' };
  if ([96, 99].includes(n)) return { emoji: '⛈️', label: 'Thunderstorm with hail' };
  return { emoji: '🌡️', label: 'Unknown conditions' };
}

function decodeEntities(value = '') {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  return String(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(Number.parseInt(h, 16)))
    .replace(/&#([0-9]+);/g, (_, d) => String.fromCodePoint(Number.parseInt(d, 10)))
    .replace(/&([a-z]+);/gi, (m, name) => named[name.toLowerCase()] ?? m);
}

function plainText(value = '') {
  return decodeEntities(value)
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function clipSentence(value, max = DESCRIPTION_LIMIT) {
  const text = plainText(value);
  if (text.length <= max) return text;
  const clipped = text.slice(0, max - 1).replace(/\s+\S*$/, '').trim();
  return `${clipped || text.slice(0, max - 1)}…`;
}

function xmlTag(block, tag) {
  const m = String(block).match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return m ? m[1] : '';
}

export function parseCbcRss(xml, limit = 7) {
  const wanted = Math.max(5, Math.min(7, Number(limit) || 7));
  const items = String(xml).match(/<item\b[\s\S]*?<\/item>/gi) || [];
  return items.slice(0, wanted).map(item => {
    const title = plainText(xmlTag(item, 'title')) || 'Untitled headline';
    const description = clipSentence(xmlTag(item, 'description'));
    const link = plainText(xmlTag(item, 'link'));
    const published = plainText(xmlTag(item, 'pubDate'));
    return { title, description, link, published };
  });
}

async function fetchText(url, fetchImpl, label) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetchImpl(url, {
      headers: { 'User-Agent': 'Pi-Local-Briefing/1.0 (+local MCP)' },
      redirect: 'follow',
      signal: controller.signal,
    });
    if (!response?.ok) throw new Error(`${label} returned HTTP ${response?.status ?? 'unknown'}`);
    return await response.text();
  } catch (error) {
    if (error?.name === 'AbortError') throw new Error(`${label} timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    const message = error?.message || String(error);
    if (message.startsWith(label)) throw error;
    throw new Error(`${label} request failed: ${message}`);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJson(url, fetchImpl, label) {
  const raw = await fetchText(url, fetchImpl, label);
  try { return JSON.parse(raw); }
  catch { throw new Error(`${label} returned invalid JSON`); }
}

function roundTemp(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.round(n) : null;
}

export function normalizeWeather(data) {
  if (!data || typeof data !== 'object') throw new Error('Open-Meteo response is empty');
  const daily = data.daily || {};
  const dates = Array.isArray(daily.time) ? daily.time : [];
  const highs = Array.isArray(daily.temperature_2m_max) ? daily.temperature_2m_max : [];
  const lows = Array.isArray(daily.temperature_2m_min) ? daily.temperature_2m_min : [];
  const codes = Array.isArray(daily.weather_code) ? daily.weather_code : [];
  if (dates.length < 7 || highs.length < 7 || lows.length < 7 || codes.length < 7) {
    throw new Error('Open-Meteo response does not contain a complete 7-day forecast');
  }
  const days = dates.slice(0, 7).map((date, i) => ({
    date,
    high: roundTemp(highs[i]),
    low: roundTemp(lows[i]),
    code: Number(codes[i]),
    ...wmoCondition(codes[i], true),
  }));
  const currentCode = Number(data.current?.weather_code);
  return {
    currentTemp: roundTemp(data.current?.temperature_2m),
    currentCode,
    current: wmoCondition(currentCode, Number(data.current?.is_day) !== 0),
    todayHigh: days[0].high,
    todayLow: days[0].low,
    days,
  };
}

function formatDate(date, options) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Toronto', ...options }).format(date);
}

function markdownSafeInline(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/([*_`])/g, '\\$1')
    .replace(/[\r\n]+/g, ' ')
    .trim();
}

export function renderBriefing({ weather, weatherError, headlines, newsError, now = new Date() }) {
  const lines = [];
  const add = line => lines.push(`> ${line}`);
  add('# 🏙️ London, ON | Daily Briefing');
  add(`**${formatDate(now, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}**`);
  add('***');
  add('');
  add('### 🌤️ Weather Forecast');
  if (weather) {
    add(`**Currently:** ${weather.current.emoji} ${weather.currentTemp ?? '—'}°C — ${weather.current.label} | **Today\'s High:** ${weather.todayHigh ?? '—'}°C | **Low:** ${weather.todayLow ?? '—'}°C`);
    add('');
    add('**7-Day Outlook:**');
    for (const day of weather.days) {
      const dayDate = new Date(`${day.date}T12:00:00Z`);
      add(`* **${formatDate(dayDate, { weekday: 'short', month: 'short', day: 'numeric' })}:** ${day.high ?? '—'}/${day.low ?? '—'}°C — ${day.emoji} ${day.label}`);
    }
  } else {
    add(`⚠️ Weather unavailable: ${markdownSafeInline(weatherError || 'Open-Meteo request failed')}`);
  }
  add('');
  add('***');
  add('');
  add('### 📰 Local Headlines');
  if (Array.isArray(headlines) && headlines.length) {
    for (const item of headlines) {
      const title = markdownSafeInline(item.title);
      const description = markdownSafeInline(item.description || 'No description provided by the feed.');
      add(`* **${title}:** ${description}`);
    }
  } else {
    add(`⚠️ Local news unavailable: ${markdownSafeInline(newsError || 'CBC London RSS request failed')}`);
  }
  return lines.join('\n');
}

export async function buildLondonDailyBriefing({ headlineCount = 7, fetchImpl = globalThis.fetch, now = new Date() } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('Fetch API is unavailable in this runtime');
  const count = Math.max(5, Math.min(7, Number(headlineCount) || 7));

  const [weatherResult, newsResult] = await Promise.allSettled([
    fetchJson(OPEN_METEO_LONDON_URL, fetchImpl, 'Open-Meteo'),
    fetchText(CBC_LONDON_RSS_URL, fetchImpl, 'CBC London RSS'),
  ]);

  let weather = null;
  let weatherError = null;
  if (weatherResult.status === 'fulfilled') {
    try { weather = normalizeWeather(weatherResult.value); }
    catch (error) { weatherError = error?.message || String(error); }
  } else weatherError = weatherResult.reason?.message || String(weatherResult.reason);

  let headlines = [];
  let newsError = null;
  if (newsResult.status === 'fulfilled') {
    try {
      headlines = parseCbcRss(newsResult.value, count);
      if (!headlines.length) newsError = 'CBC London RSS contained no readable items';
    } catch (error) { newsError = error?.message || String(error); }
  } else newsError = newsResult.reason?.message || String(newsResult.reason);

  return renderBriefing({ weather, weatherError, headlines, newsError, now });
}
