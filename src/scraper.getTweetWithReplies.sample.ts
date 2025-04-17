import { Scraper } from './scraper';
import { setTimeout } from 'node:timers/promises';

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

  const result = await scraper.getTweetWithReplies('1912460968862601417');
  if (result == null) {
    console.log('no result');
    return;
  }
  const { tweet, replies, topCursor } = result;
  let bottomCursor = result.bottomCursor;
  let showMoreThreadsCursor = result.showMoreThreadsCursor;
  console.log('got tweet', {
    id: tweet?.id,
    text: tweet?.text,
    replies: replies.map((r) => ({
      id: r.id,
      text: r.text,
      username: r.username,
      name: r.name,
    })),
    bottomCursor,
    topCursor,
    showMoreThreadsCursor,
  });
  while (bottomCursor != null || showMoreThreadsCursor != null) {
    await setTimeout(3000 + Math.floor(Math.random() * 2000));
    const result = await scraper.getTweetWithReplies(
      '1912460968862601417',
      bottomCursor || showMoreThreadsCursor,
    );
    if (result == null) {
      break;
    }
    bottomCursor = result.bottomCursor;
    showMoreThreadsCursor = result.showMoreThreadsCursor;
    console.log('got tweet', {
      replies: result.replies.map((r) => ({
        id: r.id,
        text: r.text,
        username: r.username,
        name: r.name,
      })),
      bottomCursor,
      topCursor: result.topCursor,
      showMoreThreadsCursor,
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
