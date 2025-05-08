# Kuudare
Public Repo For Kuudere.to

## Table of Contents
- [Overview](#overview)
- [Authentication](#authentication)
  - [Obtaining the Key](#obtaining-the-key)
- [User Registration & Login](#user-registration-login)
  - [Creating New Users](#creating-new-users)
  - [Authentication Flow](#authentication-flow)
- [API Endpoints](#api-endpoints)
  - [Anime Search](#anime-search)
  - [Anime Info](#anime-info)
  - [Episode Streaming](#episode-streaming)
  - [Watchlist](#watchlist)
  - [Continue Watching](#continue-watching)
  - [User Profile](#user-profile)
  - [Community](#community)
  - [Watch Rooms](#watch-rooms)
- [Complete Endpoint Reference](#endpoint-reference)

## <span id="thanks">🤝 Thanks</span>

- [Aniwatch API](https://github.com/ghoshRitesh12/aniwatch-api)

## <span id="overview">Overview</span>
This project provides documentation for the kuudere.to Anime Streaming API.

## <span id="authentication">Authentication</span>
The API requires authentication using a `key` and `secret` for each request.

### <span id="obtaining-the-key">Obtaining The Key</span>
- **URL:** `https://kuudere.to/login`
- **Method:** POST

#### Required Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | `string` | Yes | Account email used in site |
| `password` | `string` | Yes | Account password used in site |

#### Sample Request
```json
POST /login
{
  "email": "your_email@example.com",
  "password": "your_password"
}
```

#### Sample Response
```json
{
    "message":"Logged in successfully",
    "pref":{
        "autoNext":true,
        "autoPlay":false,
        "autoSkipIntro":false,
        "autoSkipOutro":false,
        "defaultComments":"false",
        "defaultLang":"japanese"
    },
    "session":{
        "expire":"2026-03-04T17:21:06.827+00:00",
        "session":"########",// Use this as 'key' when sending requests to api 
        "sessionId":"sgsgsgsg",
        "userId":"sgsfafwer3r34wwgg3"
    },
    "success":true
}
```

## <span id="user-registration-login">User Registration & Login</span>

Developers can integrate with kuudere.to's user authentication system rather than using hardcoded sessions. This allows your application to dynamically register and authenticate users through our database.

### <span id="creating-new-users">Creating New Users</span>

#### Endpoint: `/register`
- **Method**: POST
- **Description**: Register a new user in the kuudere.to system

**Body Parameters**:
- `email`: User's email address
- `username`: Desired username
- `password`: User's password

**Sample Request**:
```json
POST /register
{
  "email": "user@example.com",
  "username": "animeuser",
  "password": "securePassword123"
}
```

**Sample Response**:
```json
{
  "success": true,
  "message": "User registered successfully",
  "session": {
    "expire": "2026-03-04T17:21:06.827+00:00",
    "session": "user_session_key_here",
    "sessionId": "session_id_here",
    "userId": "user_id_here"
  }
}
```

### <span id="authentication-flow">Authentication Flow</span>

1. **Register a new user** (if they don't already have an account):
   - Use the `/register` endpoint to create a new user account

2. **Log in the user**:
   - Use the `/login` endpoint with the user's credentials
   - Store the returned session key securely

3. **Use the session for API requests**:
   - Use the returned session as the `key` parameter in subsequent API requests
   - Include your API `secret` with every request

This approach allows you to build applications with dynamic user authentication rather than using static, hardcoded session values.

#### Endpoint: `/login`
- **Method**: POST
- **Description**: Authenticate a user and retrieve session information

**Body Parameters**:
- `email`: User's email address
- `password`: User's password

**Sample Request**:
```json
POST /login
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Sample Response**:
```json
{
  "message": "Logged in successfully",
  "pref": {
    "autoNext": true,
    "autoPlay": false,
    "autoSkipIntro": false,
    "autoSkipOutro": false,
    "defaultComments": "false",
    "defaultLang": "japanese"
  },
  "session": {
    "expire": "2026-03-04T17:21:06.827+00:00",
    "session": "user_session_key", // Use this as 'key' for API requests
    "sessionId": "session_id_here",
    "userId": "user_id_here"
  },
  "success": true
}
```

## <span id="api-endpoints">API Endpoints</span>

For all API-enabled endpoints, include the following in your request body as JSON:

```json
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

### <span id="anime-search">Anime Search</span>

#### Endpoint: `/search`
- **Method**: GET/POST
- **Description**: Search for anime using various filters

**URL Parameters**:
- `keyword`: Search term
- `season`: Filter by season
- `language`: Filter by language
- `sort`: Sort order (default,score,etc)
- `genres`: Filter by genres
- `year`: Filter by year
- `type`: Filter by type
- `score`: Filter by score
- `page`: Page number

**Sample Request**:
```
GET /search?keyword=naruto&genres=action,adventure&year=2020&page=1
```
```json
POST /search
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

### <span id="anime-info">Anime Info</span>

#### Endpoint: `/anime/<id>`
- **Method**: GET/POST
- **Description**: Get detailed information about an anime

**URL Parameters**:
- `id`: Anime ID (in URL path)

**Sample Request**:
```
GET /anime/67759a9c00231b0dea36
```
```json
POST /anime/67759a9c00231b0dea36
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

### <span id="episode-streaming">Episode Streaming</span>

#### Endpoint: `/watch/<anime_id>/<ep_number>`
- **Method**: GET/POST
- **Description**: Get episode streaming information

**URL Parameters**:
- `anime_id`: Anime ID (in URL path)
- `ep_number`: Episode number (in URL path)

**Sample Request**:
```
GET /watch/67759a9c00231b0dea36/1
```
```json
POST /watch/67759a9c00231b0dea36/1
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

#### Endpoint: `/watch-api/<anime_id>/<ep_number>`
- **Method**: GET/POST
- **Description**: Get episode streaming links and information (IMPORTANT: This is the primary endpoint for obtaining all streaming links)

**URL Parameters**:
- `anime_id`: Anime ID (in URL path)
- `ep_number`: Episode number (in URL path)

**Sample Request**:
```
GET /watch-api/67759a9c00231b0dea36/1
```
```json
POST /watch-api/67759a9c00231b0dea36/1
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

**Sample Response**:
```json
{
  "success": true,
  "episode_links": [
    {
      "$id": "677d68d5001251172503",
      "continue": false,
      "serverId": 1,
      "serverName": "StreamWish",
      "episodeNumber": 1,
      "dataType": "sub",
      "dataLink": "https://hlswish.com/e/tcay002grd1q"
    },
    {
      "$id": "677d62ed0002f30f7835",
      "serverId": 1000,
      "continue": true,
      "serverName": "Hianime",
      "episodeNumber": 1,
      "dataType": "sub",
      "dataLink": "https://kuudere.to/player/Hianime/unnamed-memory-season-2-19440?ep=131525&server=hd-1&category=sub&episode=677d62ed001b25ef0fe7&anime=67759a9c00231b0dea36&vide=Hianime&api=http://127.0.0.1:5000"
    },
    {
      "$id": "jvjvh",
      "serverId": 10001,
      "continue": true,
      "serverName": "Hianime-2",
      "episodeNumber": 1,
      "dataType": "sub",
      "dataLink": "https://kuudere.to/player2/Hianime/unnamed-memory-season-2-19440?ep=131525&server=hd-1&category=sub&episode=677d62ed001b25ef0fe7&anime=67759a9c00231b0dea36&vide=Hianime-2&api=http://127.0.0.1:5000"
    }
  ],
  "episode_id": "677d62ed001b25ef0fe7",
  "duration": 1440,
  "current": 0,
  "intro_start": 0,
  "intro_end": 0,
  "outro_start": 0,
  "outro_end": 0
}
```

### <span id="watchlist">Watchlist</span>

#### Endpoint: `/add-to-watchlist/<folder>/<animeid>`
- **Method**: GET/POST
- **Description**: Add anime to watchlist

**URL Parameters**:
- `folder`: Watchlist folder name (in URL path) 
- `animeid`: Anime ID (in URL path)

**Sample Request**:
```
GET /add-to-watchlist/watching/67759a9c00231b0dea36
```
```json
POST /add-to-watchlist/watching/67759a9c00231b0dea36
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

#### Endpoint: `/api/watchlist`
- **Method**: GET/POST
- **Description**: Get user's watchlist

**URL Parameters**:
- `folder`: Folder to filter (optional)
- `page`: Page number (optional)

**Sample Request**:
```
GET /api/watchlist?folder=watching&page=1
```
```json
POST /api/watchlist
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

### <span id="continue-watching">Continue Watching</span>

#### Endpoint: `/save/progress`
- **Method**: POST
- **Description**: Save watching progress

**Body Parameters**:
- `key`: Your session key
- `secret`: Your secret
- `anime_id`: Anime ID
- `episode_id`: Episode ID
- `current`: Current time in seconds
- `duration`: Total duration in seconds

**Sample Request**:
```json
POST /save/progress
{
  "key": "your_session_key",
  "secret": "your_secret",
  "anime_id": "67759a9c00231b0dea36",
  "episode_id": "677d62ed001b25ef0fe7",
  "current": 120,
  "duration": 1440
}
```

#### Endpoint: `/api/continue-watching`
- **Method**: GET/POST
- **Description**: Get continue watching list

**URL Parameters**:
- `page`: Page number (optional)

**Sample Request**:
```
GET /api/continue-watching?page=1
```
```json
POST /api/continue-watching
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

### <span id="user-profile">User Profile</span>

#### Endpoint: `/profile`
- **Method**: GET/POST
- **Description**: Get user profile information

**Sample Request**:
```json
POST /profile
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

#### Endpoint: `/update/profile`
- **Method**: POST
- **Description**: Update user profile

**Body Parameters**:
- `key`: Your session key
- `secret`: Your secret
- `username`: New username
- `avatar`: Avatar image
- `bio`: User biography

**Sample Request**:
```json
POST /update/profile
{
  "key": "your_session_key",
  "secret": "your_secret",
  "username": "new_username",
  "bio": "My new profile bio"
}
```

### <span id="community">Community</span>

#### Endpoint: `/community`
- **Method**: GET/POST
- **Description**: Get community posts

**URL Parameters**:
- `page`: Page number (optional)
- `sort`: Sort order (optional)

**Sample Request**:
```
GET /community?page=1&sort=recent
```
```json
POST /community
{
  "key": "your_session_key",
  "secret": "your_secret"
}
```

#### Endpoint: `/anime/comment/`
- **Method**: POST
- **Description**: Add a comment to an anime

**Body Parameters**:
- `key`: Your session key
- `secret`: Your secret
- `anime_id`: Anime ID
- `episode_id`: Episode ID
- `content`: Comment content

**Sample Request**:
```json
POST /anime/comment/
{
  "key": "your_session_key",
  "secret": "your_secret",
  "anime_id": "67759a9c00231b0dea36",
  "episode_id": "677d62ed001b25ef0fe7",
  "content": "This episode was amazing!"
}
```

### <span id="watch-rooms">Watch Rooms</span>

#### Endpoint: `/create_room`
- **Method**: POST
- **Description**: Create a watch room

**Body Parameters**:
- `key`: Your session key
- `secret`: Your secret
- `anime_id`: Anime ID
- `episode_id`: Episode ID
- `name`: Room name
- `password`: Room password (optional)

**Sample Request**:
```json
POST /create_room
{
  "key": "your_session_key",
  "secret": "your_secret",
  "anime_id": "67759a9c00231b0dea36",
  "episode_id": "677d62ed001b25ef0fe7",
  "name": "Watch Party",
  "password": "optional_password"
}
```

#### Endpoint: `/send_chat`
- **Method**: POST
- **Description**: Send a chat message in a room

**Body Parameters**:
- `key`: Your session key
- `secret`: Your secret
- `room_id`: Room ID
- `message`: Chat message content

**Sample Request**:
```json
POST /send_chat
{
  "key": "your_session_key",
  "secret": "your_secret",
  "room_id": "room12345",
  "message": "Hello everyone!"
}
```

## <span id="endpoint-reference">Complete Endpoint Reference</span>

For each endpoint:
- **URL Parameters**: Sent in the URL query string (e.g., `/search?keyword=naruto&page=1`)
- **Body Parameters**: Sent in the JSON request body

| Endpoint | Method | Description | URL Parameters | Body Parameters |
|----------|--------|-------------|--------------|----------------|
| `/logout` | POST | Log out of your account | None | `key`, `secret` |
| [`/home`](#api-endpoints) | GET/POST | Get homepage data including latest episodes | `page` (optional): Page number | `key`, `secret` |
| [`/search`](#anime-search) | GET/POST | Search anime | `keyword`: Search term<br>`season`: Filter by season<br>`language`: Filter by language<br>`sort`: Sort order (default,score,etc)<br>`genres`: Filter by genres<br>`year`: Filter by year<br>`type`: Filter by type<br>`score`: Filter by score<br>`page`: Page number | `key`, `secret` |
| `/upcoming` | GET/POST | Get upcoming anime | `page`: Page number (optional) | `key`, `secret` |
| [`/anime/<id>`](#anime-info) | GET/POST | Get detailed information about an anime | `id` in URL path | `key`, `secret` |
| [`/watch/<anime_id>/<ep_number>`](#episode-streaming) | GET/POST | Get episode streaming information | `anime_id` and `ep_number` in URL path | `key`, `secret` |
| `/api/anime/respond/<id>` | POST | Like/unlike an anime | `id` in URL path | `key`, `secret`<br>`type`: Action type (like/unlike) |
| `/api/anime/comment/respond/<id>` | POST | Like/unlike an anime comment | `id` in URL path | `key`, `secret`<br>`type`: Action type (like/unlike) |
| [`/add-to-watchlist/<folder>/<animeid>`](#watchlist) | GET/POST | Add anime to watchlist | `folder` and `animeid` in URL path | `key`, `secret` |
| `/processx` | POST | Process file uploads | None | `key`, `secret`<br>`file`: File to upload |
| `/search-api` | GET | Search API for anime | `keyword`: Search term | `key`, `secret` |
| [`/watch-api/<anime_id>/<ep_number>`](#episode-streaming) | GET/POST | Get episode information | `anime_id` and `ep_number` in URL path | `key`, `secret` |
| `/api/anime/comments/<anime_id>/<ep_number>` | GET/POST | Get episode comments | `anime_id` and `ep_number` in URL path | `key`, `secret`<br>`page`: Page number (optional) |
| [`/community`](#community) | GET/POST | Get community posts | `page`: Page number (optional)<br>`sort`: Sort order (optional) | `key`, `secret` |
| `/api/posts` | GET/POST | Get list of posts | `page`: Page number (optional)<br>`sort`: Sort order (optional) | `key`, `secret` |
| `/api/post/comment/reply/<comment_id>` | POST | Reply to a post comment | `comment_id` in URL path | `key`, `secret`<br>`content`: Reply content |
| `/api/post/respond/<id>` | POST | Like/unlike a post | `id` in URL path | `key`, `secret`<br>`type`: Action type (like/unlike) |
| `/api/post/comment/respond/<id>` | POST | Like/unlike a post comment | `id` in URL path | `key`, `secret`<br>`type`: Action type (like/unlike) |
| `/post/<post_id>` | GET/POST | View a specific post | `post_id` in URL path | `key`, `secret` |
| [`/anime/comment/`](#community) | POST | Add a comment to an anime | None | `key`, `secret`<br>`anime_id`: Anime ID<br>`episode_id`: Episode ID<br>`content`: Comment content |
| `/anime/comments/reply` | POST | Reply to an anime comment | None | `key`, `secret`<br>`comment_id`: Comment ID<br>`content`: Reply content |
| [`/profile`](#user-profile) | GET/POST | Get user profile information | None | `key`, `secret` |
| `/api/profile` | GET/POST | Get API profile information | None | `key`, `secret` |
| `/api/settings` | GET/POST | Get user settings | None | `key`, `secret` |
| `/api/sync/info` | GET/POST | Sync account information | None | `key`, `secret` |
| `/api/save/settings` | POST | Save user settings | None | `key`, `secret`<br>`settings`: JSON object with user settings |
| [`/api/watchlist`](#watchlist) | GET/POST | Get user's watchlist | `folder`: Folder to filter (optional)<br>`page`: Page number (optional) | `key`, `secret` |
| [`/save/progress`](#continue-watching) | POST | Save watching progress | None | `key`, `secret`<br>`anime_id`: Anime ID<br>`episode_id`: Episode ID<br>`current`: Current time in seconds<br>`duration`: Total duration in seconds |
| `/api/continue-watching-home` | GET/POST | Get continue watching for homepage | `limit`: Number of items (optional) | `key`, `secret` |
| [`/api/continue-watching`](#continue-watching) | GET/POST | Get continue watching list | `page`: Page number (optional) | `key`, `secret` |
| `/api/realtime/anime/<id>` | GET/POST | Get real-time anime information | `id` in URL path | `key`, `secret` |
| `/api/notifications/<notification_type>` | GET/POST | Get user notifications | `notification_type` in URL path | `key`, `secret`<br>`page`: Page number (optional) |
| `/api/notifications/count` | GET/POST | Get notification count | None | `key`, `secret` |
| `/api/top/anime/` | GET/POST | Get top anime | `page`: Page number (optional)<br>`category`: Category filter (optional) | `key`, `secret` |
| `/api/top/posts` | GET/POST | Get top posts | `page`: Page number (optional)<br>`period`: Time period (optional) | `key`, `secret` |
| `/countdowns` | GET/POST | Get anime countdowns | None | `key`, `secret` |
| `/api/schedule` | GET/POST | Get anime schedule | `day`: Day of week (optional) | `key`, `secret` |
| [`/update/profile`](#user-profile) | POST | Update user profile | None | `key`, `secret`<br>`username`: New username<br>`avatar`: Avatar image<br>`bio`: User biography |
| `/recently-updated` | GET/POST | Get recently updated anime | `page`: Page number (optional) | `key`, `secret` |
| `/public/user/<id>` | GET/POST | Get public user profile | `id` in URL path | `key`, `secret` |
| `/report/anime/episode` | POST | Report an episode issue | None | `key`, `secret`<br>`anime_id`: Anime ID<br>`episode_id`: Episode ID<br>`issue`: Issue description |
| `/votes/anime/<anime_id>` | POST | Get votes for an anime | `anime_id` in URL path | `key`, `secret` |
| `/vote/anime/<anime_id>` | POST | Submit a vote for an anime | `anime_id` in URL path | `key`, `secret`<br>`vote`: Vote value |
| `/api/hover/anime/<anime_id>` | GET | Get hover data for an anime | `anime_id` in URL path | `key`, `secret` |
| [`/create_room`](#watch-rooms) | POST | Create a watch room | None | `key`, `secret`<br>`anime_id`: Anime ID<br>`episode_id`: Episode ID<br>`name`: Room name<br>`password`: Room password (optional) |
| `/get_all_rooms` | POST | Get list of all rooms | None | `key`, `secret`<br>`page`: Page number (optional) |
| `/get_room` | POST | Get specific room information | None | `key`, `secret`<br>`room_id`: Room ID |
| [`/send_chat`](#watch-rooms) | POST | Send a chat message in a room | None | `key`, `secret`<br>`room_id`: Room ID<br>`message`: Chat message content |
| [`/register`](#creating-new-users) | POST | Register a new user | None | `email`: User's email<br>`username`: Desired username<br>`password`: User's password |
| [`/login`](#authentication-flow) | POST | Log in to account | None | `email`: User's email<br>`password`: User's password |

## Notes
- Always include both `key` and `secret` in your requests
- Ensure you have the correct permissions to access the API
- Respect the API's terms of service and usage guidelines

## Disclaimer
- This documentation is based on observed API behavior and may be subject to change
- Sample responses are illustrative and may not reflect exact API output

## Contributing
- Found an issue? Please open a GitHub issue
- Have improvements? Submit a pull request