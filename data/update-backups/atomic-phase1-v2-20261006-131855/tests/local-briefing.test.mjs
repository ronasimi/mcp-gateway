import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OPEN_METEO_LONDON_URL,
  CBC_LONDON_RSS_URL,
  wmoCondition,
  parseCbcRss,
  normalizeWeather,
  renderBriefing,
  buildLondonDailyBriefing,
} from '../scripts/local-briefing.mjs';

const weatherFixture = {
  current: { temperature_2m: 16.4, weather_code: 2, is_day: 1 },
  daily: {
    time: ['2026-10-01','2026-10-02','2026-10-03','2026-10-04','2026-10-05','2026-10-06','2026-10-07'],
    temperature_2m_max: [19.3,18.1,17.6,14.4,12.2,11.8,13.7],
    temperature_2m_min: [8.2,7.9,6.4,4.1,2.2,1.8,3.7],
    weather_code: [2,61,3,71,0,45,95],
  },
};

function rssFixture(count = 7) {
  return `<?xml version="1.0"?><rss><channel>${Array.from({length: count}, (_, i) => `
    <item>
      <title><![CDATA[Headline ${i + 1} &amp; London]]></title>
      <description><![CDATA[<p>Local story ${i + 1} with <strong>details</strong> for London &amp; area.</p>]]></description>
      <link>https://www.cbc.ca/news/canada/london/story-${i + 1}</link>
      <pubDate>Thu, 01 Oct 2026 0${i}:00:00 GMT</pubDate>
    </item>`).join('')}</channel></rss>`;
}

function response(body, { status = 200 } = {}) {
  return { ok: status >= 200 && status < 300, status, text: async () => typeof body === 'string' ? body : JSON.stringify(body) };
}

test('WMO mapping covers clear, cloud, fog, rain, snow and thunderstorm families', () => {
  assert.deepEqual(wmoCondition(0, true), { emoji:'☀️', label:'Clear sky' });
  assert.equal(wmoCondition(3).emoji, '☁️');
  assert.equal(wmoCondition(45).emoji, '🌫️');
  assert.equal(wmoCondition(63).emoji, '🌧️');
  assert.equal(wmoCondition(73).emoji, '❄️');
  assert.equal(wmoCondition(95).emoji, '⛈️');
  assert.equal(wmoCondition(999).label, 'Unknown conditions');
});

test('CBC RSS parser returns at most 7 clean headlines and strips HTML/entities', () => {
  const items = parseCbcRss(rssFixture(9), 7);
  assert.equal(items.length, 7);
  assert.equal(items[0].title, 'Headline 1 & London');
  assert.equal(items[0].description, 'Local story 1 with details for London & area.');
  assert.match(items[0].link, /^https:\/\/www\.cbc\.ca\//);
});

test('weather normalization requires a complete seven-day forecast', () => {
  const weather = normalizeWeather(weatherFixture);
  assert.equal(weather.currentTemp, 16);
  assert.equal(weather.todayHigh, 19);
  assert.equal(weather.days.length, 7);
  assert.equal(weather.days[1].emoji, '🌧️');
  assert.throws(() => normalizeWeather({current:{},daily:{time:['2026-10-01']}}), /complete 7-day/);
});

test('Markdown renderer emits a blockquote card with dividers, icons and seven days', () => {
  const markdown = renderBriefing({
    weather: normalizeWeather(weatherFixture),
    headlines: parseCbcRss(rssFixture(), 7),
    now: new Date('2026-10-01T12:00:00Z'),
  });
  assert.match(markdown, /^> # 🏙️ London, ON \| Daily Briefing/m);
  assert.match(markdown, /^> \*\*\*$/m);
  assert.match(markdown, /^> ### 🌤️ Weather Forecast$/m);
  assert.match(markdown, /^> ### 📰 Local Headlines$/m);
  assert.equal((markdown.match(/^> \* \*\*(?:Thu|Fri|Sat|Sun|Mon|Tue|Wed),/gm) || []).length, 7);
  assert.equal((markdown.match(/^> \* \*\*Headline/gm) || []).length, 7);
});

test('briefing fetches exact Open-Meteo and CBC endpoints in parallel and returns formatted Markdown', async () => {
  const seen = [];
  const fetchImpl = async url => {
    seen.push(String(url));
    if (String(url).startsWith('https://api.open-meteo.com/')) return response(weatherFixture);
    if (String(url) === CBC_LONDON_RSS_URL) return response(rssFixture());
    return response('not found', {status:404});
  };
  const markdown = await buildLondonDailyBriefing({ headlineCount: 6, fetchImpl, now:new Date('2026-10-01T12:00:00Z') });
  assert.equal(seen.length, 2);
  assert.ok(seen.includes(CBC_LONDON_RSS_URL));
  assert.ok(seen.some(url => url === OPEN_METEO_LONDON_URL));
  assert.match(markdown, /\*\*Currently:\*\* ⛅ 16°C/);
  assert.equal((markdown.match(/^> \* \*\*Headline/gm) || []).length, 6);
});

test('briefing degrades gracefully when one or both network sources fail', async () => {
  const weatherOnly = await buildLondonDailyBriefing({
    fetchImpl: async url => String(url).startsWith('https://api.open-meteo.com/') ? response(weatherFixture) : response('down',{status:503}),
    now:new Date('2026-10-01T12:00:00Z'),
  });
  assert.match(weatherOnly, /Weather Forecast/);
  assert.match(weatherOnly, /Local news unavailable: CBC London RSS returned HTTP 503/);
  assert.match(weatherOnly, /7-Day Outlook/);

  const allDown = await buildLondonDailyBriefing({
    fetchImpl: async () => { throw new Error('network offline'); },
    now:new Date('2026-10-01T12:00:00Z'),
  });
  assert.match(allDown, /Weather unavailable: Open-Meteo request failed: network offline/);
  assert.match(allDown, /Local news unavailable: CBC London RSS request failed: network offline/);
});
