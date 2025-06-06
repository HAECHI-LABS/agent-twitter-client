import { Cookie } from 'tough-cookie';

type FetchParameters = [input: RequestInfo | URL, init?: RequestInit];
interface FetchTransformOptions {
    /**
     * Transforms the request options before a request is made. This executes after all of the default
     * parameters have been configured, and is stateless. It is safe to return new request options
     * objects.
     * @param args The request options.
     * @returns The transformed request options.
     */
    request: (...args: FetchParameters) => FetchParameters | Promise<FetchParameters>;
    /**
     * Transforms the response after a request completes. This executes immediately after the request
     * completes, and is stateless. It is safe to return a new response object.
     * @param response The response object.
     * @returns The transformed response object.
     */
    response: (response: Response) => Response | Promise<Response>;
}

/**
 * A parsed profile object.
 */
interface Profile {
    avatar?: string;
    banner?: string;
    biography?: string;
    birthday?: string;
    followersCount?: number;
    followingCount?: number;
    friendsCount?: number;
    mediaCount?: number;
    statusesCount?: number;
    isPrivate?: boolean;
    isVerified?: boolean;
    isBlueVerified?: boolean;
    joined?: Date;
    likesCount?: number;
    listedCount?: number;
    location: string;
    name?: string;
    pinnedTweetIds?: string[];
    tweetsCount?: number;
    url?: string;
    userId?: string;
    username?: string;
    website?: string;
    canDm?: boolean;
}

interface GrokMessage {
    role: 'user' | 'assistant';
    content: string;
}
interface GrokChatOptions {
    messages: GrokMessage[];
    conversationId?: string;
    returnSearchResults?: boolean;
    returnCitations?: boolean;
}
interface GrokRateLimit {
    isRateLimited: boolean;
    message: string;
    upsellInfo?: {
        usageLimit: string;
        quotaDuration: string;
        title: string;
        message: string;
    };
}
interface GrokChatResponse {
    conversationId: string;
    message: string;
    messages: GrokMessage[];
    webResults?: any[];
    metadata?: any;
    rateLimit?: GrokRateLimit;
}

interface DirectMessage {
    id: string;
    text: string;
    senderId: string;
    recipientId: string;
    createdAt: string;
    mediaUrls?: string[];
    senderScreenName?: string;
    recipientScreenName?: string;
}
interface DirectMessageConversation {
    conversationId: string;
    messages: DirectMessage[];
    participants: {
        id: string;
        screenName: string;
    }[];
}
interface DirectMessagesResponse {
    conversations: DirectMessageConversation[];
    users: TwitterUser[];
    cursor?: string;
    lastSeenEventId?: string;
    trustedLastSeenEventId?: string;
    untrustedLastSeenEventId?: string;
    inboxTimelines?: {
        trusted?: {
            status: string;
            minEntryId?: string;
        };
        untrusted?: {
            status: string;
            minEntryId?: string;
        };
    };
    userId: string;
}
interface TwitterUser {
    id: string;
    screenName: string;
    name: string;
    profileImageUrl: string;
    description?: string;
    verified?: boolean;
    protected?: boolean;
    followersCount?: number;
    friendsCount?: number;
}
interface SendDirectMessageResponse {
    entries: {
        message: {
            id: string;
            time: string;
            affects_sort: boolean;
            conversation_id: string;
            message_data: {
                id: string;
                time: string;
                recipient_id: string;
                sender_id: string;
                text: string;
            };
        };
    }[];
    users: Record<string, TwitterUser>;
}

interface TimelineArticle {
    id: string;
    articleId: string;
    title: string;
    previewText: string;
    coverMediaUrl?: string;
    text: string;
}

interface Mention {
    id: string;
    username?: string;
    name?: string;
}
interface Photo {
    id: string;
    url: string;
    alt_text: string | undefined;
}
interface Video {
    id: string;
    preview: string;
    url?: string;
}
interface PlaceRaw {
    id?: string;
    place_type?: string;
    name?: string;
    full_name?: string;
    country_code?: string;
    country?: string;
    bounding_box?: {
        type?: string;
        coordinates?: number[][][];
    };
}
/**
 * A parsed Tweet object.
 */
interface Tweet {
    bookmarkCount?: number;
    conversationId?: string;
    hashtags: string[];
    html?: string;
    id?: string;
    inReplyToStatus?: Tweet;
    inReplyToStatusId?: string;
    isQuoted?: boolean;
    isPin?: boolean;
    isReply?: boolean;
    isRetweet?: boolean;
    isSelfThread?: boolean;
    language?: string;
    likes?: number;
    name?: string;
    mentions: Mention[];
    permanentUrl?: string;
    photos: Photo[];
    place?: PlaceRaw;
    quotedStatus?: Tweet;
    quotedStatusId?: string;
    quotes?: number;
    replies?: number;
    retweets?: number;
    retweetedStatus?: Tweet;
    retweetedStatusId?: string;
    text?: string;
    thread: Tweet[];
    timeParsed?: Date;
    timestamp?: number;
    urls: string[];
    userId?: string;
    username?: string;
    videos: Video[];
    views?: number;
    sensitiveContent?: boolean;
}
interface Retweeter {
    rest_id: string;
    screen_name: string;
    name: string;
    description?: string;
}
type TweetQuery = Partial<Tweet> | ((tweet: Tweet) => boolean | Promise<boolean>);

/**
 * A paginated tweets API response. The `next` field can be used to fetch the next page of results,
 * and the `previous` can be used to fetch the previous results (or results created after the
 * initial request)
 */
interface QueryTweetsResponse {
    tweets: Tweet[];
    next?: string;
    previous?: string;
}
/**
 * A paginated profiles API response. The `next` field can be used to fetch the next page of results.
 */
interface QueryProfilesResponse {
    profiles: Profile[];
    next?: string;
    previous?: string;
}

/**
 * The categories that can be used in Twitter searches.
 */
declare enum SearchMode {
    Top = 0,
    Latest = 1,
    Photos = 2,
    Videos = 3,
    Users = 4
}

/**
 * Represents a Community that can host Spaces.
 */
interface Community {
    id: string;
    name: string;
    rest_id: string;
}
/**
 * Represents a Subtopic within a Category.
 */
interface Subtopic {
    icon_url: string;
    name: string;
    topic_id: string;
}
/**
 * Represents the result details of a Creator.
 */
interface CreatorResult {
    __typename: string;
    id: string;
    rest_id: string;
    affiliates_highlighted_label: Record<string, any>;
    has_graduated_access: boolean;
    is_blue_verified: boolean;
    profile_image_shape: string;
    legacy: {
        following: boolean;
        can_dm: boolean;
        can_media_tag: boolean;
        created_at: string;
        default_profile: boolean;
        default_profile_image: boolean;
        description: string;
        entities: {
            description: {
                urls: any[];
            };
        };
        fast_followers_count: number;
        favourites_count: number;
        followers_count: number;
        friends_count: number;
        has_custom_timelines: boolean;
        is_translator: boolean;
        listed_count: number;
        location: string;
        media_count: number;
        name: string;
        needs_phone_verification: boolean;
        normal_followers_count: number;
        pinned_tweet_ids_str: string[];
        possibly_sensitive: boolean;
        profile_image_url_https: string;
        profile_interstitial_type: string;
        screen_name: string;
        statuses_count: number;
        translator_type: string;
        verified: boolean;
        want_retweets: boolean;
        withheld_in_countries: string[];
    };
    tipjar_settings: Record<string, any>;
}
/**
 * Represents user results within an Admin.
 */
interface UserResults {
    rest_id: string;
    result: {
        __typename: string;
        identity_profile_labels_highlighted_label: Record<string, any>;
        is_blue_verified: boolean;
        legacy: Record<string, any>;
    };
}
/**
 * Represents an Admin participant in an Audio Space.
 */
interface Admin {
    periscope_user_id: string;
    start: number;
    twitter_screen_name: string;
    display_name: string;
    avatar_url: string;
    is_verified: boolean;
    is_muted_by_admin: boolean;
    is_muted_by_guest: boolean;
    user_results: UserResults;
}
/**
 * Represents Participants in an Audio Space.
 */
interface Participants {
    total: number;
    admins: Admin[];
    speakers: any[];
    listeners: any[];
}
/**
 * Represents Metadata of an Audio Space.
 */
interface Metadata {
    rest_id: string;
    state: string;
    media_key: string;
    created_at: number;
    started_at: number;
    ended_at: string;
    updated_at: number;
    content_type: string;
    creator_results: {
        result: CreatorResult;
    };
    conversation_controls: number;
    disallow_join: boolean;
    is_employee_only: boolean;
    is_locked: boolean;
    is_muted: boolean;
    is_space_available_for_clipping: boolean;
    is_space_available_for_replay: boolean;
    narrow_cast_space_type: number;
    no_incognito: boolean;
    total_replay_watched: number;
    total_live_listeners: number;
    tweet_results: Record<string, any>;
    max_guest_sessions: number;
    max_admin_capacity: number;
}
/**
 * Represents Sharings within an Audio Space.
 */
interface Sharings {
    items: any[];
    slice_info: Record<string, any>;
}
/**
 * Represents an Audio Space.
 */
interface AudioSpace {
    metadata: Metadata;
    is_subscribed: boolean;
    participants: Participants;
    sharings: Sharings;
}
interface LiveVideoSource {
    location: string;
    noRedirectPlaybackUrl: string;
    status: string;
    streamType: string;
}
interface LiveVideoStreamStatus {
    source: LiveVideoSource;
    sessionId: string;
    chatToken: string;
    lifecycleToken: string;
    shareUrl: string;
    chatPermissionType: string;
}
interface LoginTwitterTokenResponse {
    cookie: string;
    user: {
        class_name: string;
        id: string;
        created_at: string;
        is_beta_user: boolean;
        is_employee: boolean;
        is_twitter_verified: boolean;
        verified_type: number;
        is_bluebird_user: boolean;
        twitter_screen_name: string;
        username: string;
        display_name: string;
        description: string;
        profile_image_urls: {
            url: string;
            ssl_url: string;
            width: number;
            height: number;
        }[];
        twitter_id: string;
        initials: string;
        n_followers: number;
        n_following: number;
    };
    type: string;
}

interface ScraperOptions {
    /**
     * An alternative fetch function to use instead of the default fetch function. This may be useful
     * in nonstandard runtime environments, such as edge workers.
     */
    fetch: typeof fetch;
    /**
     * Additional options that control how requests and responses are processed. This can be used to
     * proxy requests through other hosts, for example.
     */
    transform: Partial<FetchTransformOptions>;
}
/**
 * An interface to Twitter's undocumented API.
 * - Reusing Scraper objects is recommended to minimize the time spent authenticating unnecessarily.
 */
declare class Scraper {
    private readonly options?;
    private auth;
    private token;
    /**
     * Creates a new Scraper object.
     * - Scrapers maintain their own guest tokens for Twitter's internal API.
     * - Reusing Scraper objects is recommended to minimize the time spent authenticating unnecessarily.
     */
    constructor(options?: Partial<ScraperOptions> | undefined);
    /**
     * Fetches a Twitter profile.
     * @param username The Twitter username of the profile to fetch, without an `@` at the beginning.
     * @returns The requested {@link Profile}.
     */
    getProfile(username: string): Promise<Profile>;
    /**
     * Fetches the user ID corresponding to the provided screen name.
     * @param screenName The Twitter screen name of the profile to fetch.
     * @returns The ID of the corresponding account.
     */
    getUserIdByScreenName(screenName: string): Promise<string>;
    /**
     *
     * @param userId The user ID of the profile to fetch.
     * @returns The screen name of the corresponding account.
     */
    getScreenNameByUserId(userId: string): Promise<string>;
    getProfileByUserId(userId: string): Promise<Profile>;
    /**
     * Fetches tweets from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxTweets The maximum number of tweets to return.
     * @param includeReplies Whether or not replies should be included in the response.
     * @param searchMode The category filter to apply to the search. Defaults to `Top`.
     * @returns An {@link AsyncGenerator} of tweets matching the provided filters.
     */
    searchTweets(query: string, maxTweets: number, searchMode?: SearchMode): AsyncGenerator<Tweet, void>;
    /**
     * Fetches profiles from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxProfiles The maximum number of profiles to return.
     * @returns An {@link AsyncGenerator} of tweets matching the provided filter(s).
     */
    searchProfiles(query: string, maxProfiles: number): AsyncGenerator<Profile, void>;
    /**
     * Fetches tweets from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxTweets The maximum number of tweets to return.
     * @param includeReplies Whether or not replies should be included in the response.
     * @param searchMode The category filter to apply to the search. Defaults to `Top`.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchSearchTweets(query: string, maxTweets: number, searchMode: SearchMode, cursor?: string): Promise<QueryTweetsResponse>;
    /**
     * Fetches profiles from Twitter.
     * @param query The search query. Any Twitter-compatible query format can be used.
     * @param maxProfiles The maximum number of profiles to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchSearchProfiles(query: string, maxProfiles: number, cursor?: string): Promise<QueryProfilesResponse>;
    /**
     * Fetches list tweets from Twitter.
     * @param listId The list id
     * @param maxTweets The maximum number of tweets to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchListTweets(listId: string, maxTweets: number, cursor?: string): Promise<QueryTweetsResponse>;
    /**
     * Fetch the profiles a user is following
     * @param userId The user whose following should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @returns An {@link AsyncGenerator} of following profiles for the provided user.
     */
    getFollowing(userId: string, maxProfiles: number): AsyncGenerator<Profile, void>;
    /**
     * Fetch the profiles that follow a user
     * @param userId The user whose followers should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @returns An {@link AsyncGenerator} of profiles following the provided user.
     */
    getFollowers(userId: string, maxProfiles: number): AsyncGenerator<Profile, void>;
    /**
     * Fetches following profiles from Twitter.
     * @param userId The user whose following should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchProfileFollowing(userId: string, maxProfiles: number, cursor?: string): Promise<QueryProfilesResponse>;
    /**
     * Fetches profile followers from Twitter.
     * @param userId The user whose following should be returned
     * @param maxProfiles The maximum number of profiles to return.
     * @param cursor The search cursor, which can be passed into further requests for more results.
     * @returns A page of results, containing a cursor that can be used in further requests.
     */
    fetchProfileFollowers(userId: string, maxProfiles: number, cursor?: string): Promise<QueryProfilesResponse>;
    /**
     * Fetches the home timeline for the current user. (for you feed)
     * @param count The number of tweets to fetch.
     * @param seenTweetIds An array of tweet IDs that have already been seen.
     * @returns A promise that resolves to the home timeline response.
     */
    fetchHomeTimeline(count: number, seenTweetIds: string[]): Promise<any[]>;
    /**
     * Fetches the home timeline for the current user. (following feed)
     * @param count The number of tweets to fetch.
     * @param seenTweetIds An array of tweet IDs that have already been seen.
     * @returns A promise that resolves to the home timeline response.
     */
    fetchFollowingTimeline(count: number, seenTweetIds: string[]): Promise<any[]>;
    getUserTweets(userId: string, maxTweets?: number, cursor?: string): Promise<{
        tweets: Tweet[];
        next?: string;
    }>;
    getUserTweetsIterator(userId: string, maxTweets?: number): AsyncGenerator<Tweet, void>;
    /**
     * Fetches tweets from a Twitter user.
     * @param user The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweets(user: string, maxTweets?: number): AsyncGenerator<Tweet>;
    /**
     * Fetches tweets from a Twitter user using their ID.
     * @param userId The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweetsByUserId(userId: string, maxTweets?: number): AsyncGenerator<Tweet, void>;
    /**
     * Send a tweet
     * @param text The text of the tweet
     * @param tweetId The id of the tweet to reply to
     * @param mediaData Optional media data
     * @returns
     */
    sendTweet(text: string, replyToTweetId?: string, mediaData?: {
        data: Buffer;
        mediaType: string;
    }[], hideLinkPreview?: boolean): Promise<Response>;
    sendNoteTweet(text: string, replyToTweetId?: string, mediaData?: {
        data: Buffer;
        mediaType: string;
    }[]): Promise<any>;
    /**
     * Send a long tweet (Note Tweet)
     * @param text The text of the tweet
     * @param tweetId The id of the tweet to reply to
     * @param mediaData Optional media data
     * @returns
     */
    sendLongTweet(text: string, replyToTweetId?: string, mediaData?: {
        data: Buffer;
        mediaType: string;
    }[]): Promise<Response>;
    /**
     * Fetches tweets and replies from a Twitter user.
     * @param user The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweetsAndReplies(user: string, maxTweets?: number): AsyncGenerator<Tweet>;
    /**
     * Fetches tweets and replies from a Twitter user using their ID.
     * @param userId The user whose tweets should be returned.
     * @param maxTweets The maximum number of tweets to return. Defaults to `200`.
     * @returns An {@link AsyncGenerator} of tweets from the provided user.
     */
    getTweetsAndRepliesByUserId(userId: string, maxTweets?: number): AsyncGenerator<Tweet, void>;
    /**
     * Fetches the first tweet matching the given query.
     *
     * Example:
     * ```js
     * const timeline = scraper.getTweets('user', 200);
     * const retweet = await scraper.getTweetWhere(timeline, { isRetweet: true });
     * ```
     * @param tweets The {@link AsyncIterable} of tweets to search through.
     * @param query A query to test **all** tweets against. This may be either an
     * object of key/value pairs or a predicate. If this query is an object, all
     * key/value pairs must match a {@link Tweet} for it to be returned. If this query
     * is a predicate, it must resolve to `true` for a {@link Tweet} to be returned.
     * - All keys are optional.
     * - If specified, the key must be implemented by that of {@link Tweet}.
     */
    getTweetWhere(tweets: AsyncIterable<Tweet>, query: TweetQuery): Promise<Tweet | null>;
    /**
     * Fetches all tweets matching the given query.
     *
     * Example:
     * ```js
     * const timeline = scraper.getTweets('user', 200);
     * const retweets = await scraper.getTweetsWhere(timeline, { isRetweet: true });
     * ```
     * @param tweets The {@link AsyncIterable} of tweets to search through.
     * @param query A query to test **all** tweets against. This may be either an
     * object of key/value pairs or a predicate. If this query is an object, all
     * key/value pairs must match a {@link Tweet} for it to be returned. If this query
     * is a predicate, it must resolve to `true` for a {@link Tweet} to be returned.
     * - All keys are optional.
     * - If specified, the key must be implemented by that of {@link Tweet}.
     */
    getTweetsWhere(tweets: AsyncIterable<Tweet>, query: TweetQuery): Promise<Tweet[]>;
    /**
     * Fetches the most recent tweet from a Twitter user.
     * @param user The user whose latest tweet should be returned.
     * @param includeRetweets Whether or not to include retweets. Defaults to `false`.
     * @returns The {@link Tweet} object or `null`/`undefined` if it couldn't be fetched.
     */
    getLatestTweet(user: string, includeRetweets?: boolean, max?: number): Promise<Tweet | null | void>;
    /**
     * Fetches a single tweet.
     * @param id The ID of the tweet to fetch.
     * @returns The {@link Tweet} object, or `null` if it couldn't be fetched.
     */
    getTweet(id: string): Promise<Tweet | null>;
    /**
     * buttom cutsor 나 show more threads cursor 를 사용하세요.
     * show more threads cursor 는 x 가 spam 일 수 있다고 판단한 경우 나오는 커서입니다.
     */
    getTweetWithReplies(id: string, cursor?: string): Promise<{
        tweet: Tweet | null;
        replies: Tweet[];
        bottomCursor: string | undefined;
        topCursor: string | undefined;
        showMoreThreadsCursor: string | undefined;
    } | null>;
    /**
     * Returns if the scraper has a guest token. The token may not be valid.
     * @returns `true` if the scraper has a guest token; otherwise `false`.
     */
    hasGuestToken(): boolean;
    /**
     * Returns if the scraper is logged in as a real user.
     * @returns `true` if the scraper is logged in with a real user account; otherwise `false`.
     */
    isLoggedIn(): Promise<boolean>;
    /**
     * Returns the currently logged in user
     * @returns The currently logged in user
     */
    me(): Promise<Profile | undefined>;
    /**
     * Login to Twitter as a real Twitter account. This enables running
     * searches.
     * @param username The username of the Twitter account to login with.
     * @param password The password of the Twitter account to login with.
     * @param email The email to log in with, if you have email confirmation enabled.
     * @param twoFactorSecret The secret to generate two factor authentication tokens with, if you have two factor authentication enabled.
     */
    login(username: string, password: string, email?: string, twoFactorSecret?: string): Promise<void>;
    /**
     * Log out of Twitter.
     */
    logout(): Promise<void>;
    /**
     * Retrieves all cookies for the current session.
     * @returns All cookies for the current session.
     */
    getCookies(): Promise<Cookie[]>;
    /**
     * Set cookies for the current session.
     * @param cookies The cookies to set for the current session.
     */
    setCookies(cookies: (string | Cookie)[]): Promise<void>;
    /**
     * Clear all cookies for the current session.
     */
    clearCookies(): Promise<void>;
    /**
     * Sets the optional cookie to be used in requests.
     * @param _cookie The cookie to be used in requests.
     * @deprecated This function no longer represents any part of Twitter's auth flow.
     * @returns This scraper instance.
     */
    withCookie(_cookie: string): Scraper;
    /**
     * Sets the optional CSRF token to be used in requests.
     * @param _token The CSRF token to be used in requests.
     * @deprecated This function no longer represents any part of Twitter's auth flow.
     * @returns This scraper instance.
     */
    withXCsrfToken(_token: string): Scraper;
    /**
     * Sends a quote tweet.
     * @param text The text of the tweet.
     * @param quotedTweetId The ID of the tweet to quote.
     * @param options Optional parameters, such as media data.
     * @returns The response from the Twitter API.
     */
    sendQuoteTweet(text: string, quotedTweetId: string, options?: {
        mediaData: {
            data: Buffer;
            mediaType: string;
        }[];
    }): Promise<Response>;
    /**
     * Likes a tweet with the given tweet ID.
     * @param tweetId The ID of the tweet to like.
     * @returns A promise that resolves when the tweet is liked.
     */
    likeTweet(tweetId: string): Promise<void>;
    /**
     * Retweets a tweet with the given tweet ID.
     * @param tweetId The ID of the tweet to retweet.
     * @returns A promise that resolves when the tweet is retweeted.
     */
    retweet(tweetId: string): Promise<void>;
    /**
     * Follows a user with the given user ID.
     * @param userId The user ID of the user to follow.
     * @returns A promise that resolves when the user is followed.
     */
    followUser(userName: string): Promise<void>;
    /**
     * Fetches direct message conversations
     * @param count Number of conversations to fetch (default: 50)
     * @param cursor Pagination cursor for fetching more conversations
     * @returns Array of DM conversations and other details
     */
    getDirectMessageConversations(userId: string, cursor?: string): Promise<DirectMessagesResponse>;
    /**
     * Sends a direct message to a user.
     * @param conversationId The ID of the conversation to send the message to.
     * @param text The text of the message to send.
     * @returns The response from the Twitter API.
     */
    sendDirectMessage(conversationId: string, text: string): Promise<SendDirectMessageResponse>;
    private getAuthOptions;
    private handleResponse;
    /**
     * Retrieves the details of an Audio Space by its ID.
     * @param id The ID of the Audio Space.
     * @returns The details of the Audio Space.
     */
    getAudioSpaceById(id: string): Promise<AudioSpace>;
    /**
     * Retrieves available space topics.
     * @returns An array of space topics.
     */
    browseSpaceTopics(): Promise<Subtopic[]>;
    /**
     * Retrieves available communities.
     * @returns An array of communities.
     */
    communitySelectQuery(): Promise<Community[]>;
    /**
     * Retrieves the status of an Audio Space stream by its media key.
     * @param mediaKey The media key of the Audio Space.
     * @returns The status of the Audio Space stream.
     */
    getAudioSpaceStreamStatus(mediaKey: string): Promise<LiveVideoStreamStatus>;
    /**
     * Retrieves the status of an Audio Space by its ID.
     * This method internally fetches the Audio Space to obtain the media key,
     * then retrieves the stream status using the media key.
     * @param audioSpaceId The ID of the Audio Space.
     * @returns The status of the Audio Space stream.
     */
    getAudioSpaceStatus(audioSpaceId: string): Promise<LiveVideoStreamStatus>;
    /**
     * Authenticates Periscope to obtain a token.
     * @returns The Periscope authentication token.
     */
    authenticatePeriscope(): Promise<string>;
    /**
     * Logs in to Twitter via Proxsee using the Periscope JWT.
     * @param jwt The JWT obtained from AuthenticatePeriscope.
     * @returns The response containing the cookie and user information.
     */
    loginTwitterToken(jwt: string): Promise<LoginTwitterTokenResponse>;
    /**
     * Orchestrates the flow: get token -> login -> return Periscope cookie
     */
    getPeriscopeCookie(): Promise<string>;
    /**
     * Fetches a article (long form tweet) by its ID.
     * @param id The ID of the article to fetch. In the format of (http://x.com/i/article/id)
     * @returns The {@link TimelineArticle} object, or `null` if it couldn't be fetched.
     */
    getArticle(id: string): Promise<TimelineArticle | null>;
    /**
     * Creates a new conversation with Grok.
     * @returns A promise that resolves to the conversation ID string.
     */
    createGrokConversation(): Promise<string>;
    /**
     * Interact with Grok in a chat-like manner.
     * @param options The options for the Grok chat interaction.
     * @param {GrokMessage[]} options.messages - Array of messages in the conversation.
     * @param {string} [options.conversationId] - Optional ID of an existing conversation.
     * @param {boolean} [options.returnSearchResults] - Whether to return search results.
     * @param {boolean} [options.returnCitations] - Whether to return citations.
     * @returns A promise that resolves to the Grok chat response.
     */
    grokChat(options: GrokChatOptions): Promise<GrokChatResponse>;
    /**
     * Retrieves all users who retweeted the given tweet.
     * @param tweetId The ID of the tweet.
     * @returns An array of users (retweeters).
     */
    getRetweetersOfTweet(tweetId: string): Promise<Retweeter[]>;
    /**
     * Fetches all tweets quoting a given tweet ID by chaining requests
     * until no more pages are available.
     * @param quotedTweetId The tweet ID to find quotes of.
     * @param maxTweetsPerPage Max tweets per page (default 20).
     * @returns An array of all Tweet objects referencing the given tweet.
     */
    getAllQuotedTweets(quotedTweetId: string, maxTweetsPerPage?: number): Promise<Tweet[]>;
    getQuotedTweets(quotedTweetId: string, cursor?: string): Promise<{
        next: string | undefined;
        tweets: Tweet[];
    }>;
}

export { type Profile, type QueryProfilesResponse, type QueryTweetsResponse, Scraper, SearchMode, type Tweet };
