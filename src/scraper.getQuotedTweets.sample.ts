import { setTimeout } from 'node:timers/promises';
import { Scraper } from './scraper';

globalThis.PLATFORM_NODE = true;
globalThis.PLATFORM_NODE_JEST = false;

async function main() {
  const scraper = new Scraper();
  await scraper.setCookies(getCookies());

  const isLoggedIn = await scraper.isLoggedIn();
  console.log('isLoggedIn', isLoggedIn);

  const profile = await scraper.me();
  console.log('got profile', {
    name: profile?.name,
    username: profile?.username,
    id: profile?.userId,
  });

  const result = await scraper.getQuotedTweets('1906664938875298225');
  if (result == null) {
    console.log('no result');
    return;
  }
  const { tweets, next } = result;
  let cursor = next;
  console.log('got tweets', {
    tweets: tweets.map((t) => ({
      id: t.id,
      text: t.text,
      username: t.username,
      name: t.name,
    })),
    cursor,
  });
  while (cursor != null) {
    await setTimeout(3000 + Math.floor(Math.random() * 2000));
    const result = await scraper.getQuotedTweets(
      '1906664938875298225',
      cursor,
    );
    if (result == null) {
      break;
    }
    cursor = result.next;
    console.log('got tweets', {
      tweets: result.tweets.map((t) => ({
        id: t.id,
        text: t.text,
        username: t.username,
        name: t.name,
      })),
      cursor,
    });
  }
}

main().catch(console.error);

function getCookies() {
  const encoded = '';

  const parsedCookies = JSON.parse(
    Buffer.from(encoded, 'base64').toString('utf-8'),
  );

  return parsedCookies;
}
