# Kuudare
Public Repo For Kuudere.to

## <span id="thanks">🤝 Thanks</span>

- [Aniwatch API](https://github.com/ghoshRitesh12/aniwatch-api)



# kuudere.to Anime API Documentation

## Overview
This project provides documentation for the kuudere.to Anime Streaming API.

## Understanding
- **KEY :** Is your account or user's account secret you can obtain it via `/login` endpoint
- **SECRET :**  Have To obtain via our discord server


### 1. Obtaining The Key
- **URL:** `https://kuudere.to/login`
- **Method:** POST

#### Required Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | `string` | Yes | Account email used in site |
| `password` | `string` | Yes | Account password used in site |

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


 
## Authentication
The API requires authentication using a `key` and `secret` for each request.

## Endpoints

### 1. Home Endpoint
- **URL:** `https://kuudere.to/home`
- **Method:** POST

#### Required Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | `string` | Yes | Authentication key |
| `secret` | `string` | Yes | Authentication secret |

#### Sample Response
```json
{
    "lastUpdated": [
        {
            "id": "67759a9c00231b0dea36",
            "english": "Unnamed Memory Season 2",
            "romaji": "Unnamed Memory Act.2",
            "native": "Unnamed Memory Act.2",
            "ageRating": "PG-13",
            "malScore": 7.15,
            "averageScore": 68,
            "duration": 24,
            "genres": [
                "Adventure",
                "Fantasy",
                "Romance"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/medium/bx178550-1mjYHtOwiqkC.jpg",
            "season": "WINTER",
            "startDate": "Jan 07, 2025",
            "status": "RELEASING",
            "synonyms": [
                "Unnamed Memory \u7b2c2\u671f",
                "Unnamed Memory 2nd Season",
                "\u30a2\u30f3\u30cd\u30fc\u30e0\u30c9\u30e1\u30e2\u30ea\u30fc Act.2"
            ],
            "type": "TV",
            "year": 2025,
            "epCount": 9,
            "subbedCount": 9,
            "dubbedCount": 0,
            "description": "The second season of <i>Unnamed Memory</i>.<br>\n<br>\nSeeking to end a curse thwarting his lineage, Prince Oscar sets out on a quest that leads him to a powerful and beautiful witch, Tinasha, and he demands a unique bargain: marriage. Though unenthused by the proposal, she agrees to stay in his castle for a year while researching the spell cast upon him. But beneath her beauty lies a lifetime of dark secrets that soon come to light.<br>\n<br>\n(Source: Crunchyroll)"
        },
        {
            "id": "675c236b0027b1bff29c",
            "english": "Tying the Knot with an Amagami Sister",
            "romaji": "Amagami-san Chi no Enmusubi",
            "native": "\u7518\u795e\u3055\u3093\u3061\u306e\u7e01\u7d50\u3073",
            "ageRating": "PG-13",
            "malScore": 7.16,
            "averageScore": 69,
            "duration": 24,
            "genres": [
                "Comedy",
                "Drama",
                "Ecchi",
                "Romance",
                "Supernatural"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/medium/bx164172-GY2aqItIuqtR.jpg",
            "season": "FALL",
            "startDate": "Oct 02, 2024",
            "status": "RELEASING",
            "synonyms": [
                "Matchmaking of the Amagami Household",
                "\u0e14\u0e49\u0e32\u0e22\u0e41\u0e14\u0e07\u0e1c\u0e39\u0e01\u0e23\u0e31\u0e01\u0e1a\u0e49\u0e32\u0e19\u0e2d\u0e32\u0e21\u0e32\u0e01\u0e32\u0e21\u0e34",
                "\u7d50\u7de3\u7518\u795e\u795e\u793e",
                "\u7518\u795e\u5bb6\u7684\u8fde\u7406\u679d",
                "\u0631\u0628\u0637 \u0627\u0644\u0639\u0642\u062f \u0645\u0639 \u0623\u062e\u0648\u0627\u062a \u0623\u0645\u0627\u063a\u0627\u0645\u064a"
            ],
            "type": "TV",
            "year": 2024,
            "epCount": 21,
            "subbedCount": 21,
            "dubbedCount": 17,
            "description": "Uryuu Kamihate is a high school student striving to enter Kyoto University\u2019s medical school. After being raised at an orphanage, Uryuu is taken in by the chief priest at Amagami Shrine, where he begins to live as a freeloader\u2014and to cohabit with Yae, Yuna, and Asahi, the three beautiful shrine maiden sisters! What\u2019s more, the condition he must meet in order to live at the shrine for free is to marry into the family and inherit the shrine! How will Uryuu overcome his marriage meetings with the three sisters as well as the many challenges that Amagami Shrine faces? So begins a miraculous rom-com about living under the same roof with three shrine maidens!<br>\n<br>\n(Source: Crunchyroll, edited)"
        },
    ],
    "latestEps": [
        {
            "id": "67759a9c00231b0dea36",
            "english": "Unnamed Memory Season 2",
            "romaji": "Unnamed Memory Act.2",
            "native": "Unnamed Memory Act.2",
            "ageRating": "PG-13",
            "malScore": 7.15,
            "averageScore": 68,
            "duration": 24,
            "genres": [
                "Adventure",
                "Fantasy",
                "Romance"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/medium/bx178550-1mjYHtOwiqkC.jpg",
            "season": "WINTER",
            "startDate": "Jan 07, 2025",
            "status": "RELEASING",
            "synonyms": [
                "Unnamed Memory \u7b2c2\u671f",
                "Unnamed Memory 2nd Season",
                "\u30a2\u30f3\u30cd\u30fc\u30e0\u30c9\u30e1\u30e2\u30ea\u30fc Act.2"
            ],
            "type": "TV",
            "year": 2025,
            "epCount": 9,
            "subbedCount": 9,
            "dubbedCount": 0,
            "description": "The second season of <i>Unnamed Memory</i>.<br>\n<br>\nSeeking to end a curse thwarting his lineage, Prince Oscar sets out on a quest that leads him to a powerful and beautiful witch, Tinasha, and he demands a unique bargain: marriage. Though unenthused by the proposal, she agrees to stay in his castle for a year while researching the spell cast upon him. But beneath her beauty lies a lifetime of dark secrets that soon come to light.<br>\n<br>\n(Source: Crunchyroll)",
            "url": "/watch/67759a9c00231b0dea36/9"
        },
        {
            "id": "675c236b0027b1bff29c",
            "english": "Tying the Knot with an Amagami Sister",
            "romaji": "Amagami-san Chi no Enmusubi",
            "native": "\u7518\u795e\u3055\u3093\u3061\u306e\u7e01\u7d50\u3073",
            "ageRating": "PG-13",
            "malScore": 7.16,
            "averageScore": 69,
            "duration": 24,
            "genres": [
                "Comedy",
                "Drama",
                "Ecchi",
                "Romance",
                "Supernatural"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/medium/bx164172-GY2aqItIuqtR.jpg",
            "season": "FALL",
            "startDate": "Oct 02, 2024",
            "status": "RELEASING",
            "synonyms": [
                "Matchmaking of the Amagami Household",
                "\u0e14\u0e49\u0e32\u0e22\u0e41\u0e14\u0e07\u0e1c\u0e39\u0e01\u0e23\u0e31\u0e01\u0e1a\u0e49\u0e32\u0e19\u0e2d\u0e32\u0e21\u0e32\u0e01\u0e32\u0e21\u0e34",
                "\u7d50\u7de3\u7518\u795e\u795e\u793e",
                "\u7518\u795e\u5bb6\u7684\u8fde\u7406\u679d",
                "\u0631\u0628\u0637 \u0627\u0644\u0639\u0642\u062f \u0645\u0639 \u0623\u062e\u0648\u0627\u062a \u0623\u0645\u0627\u063a\u0627\u0645\u064a"
            ],
            "type": "TV",
            "year": 2024,
            "epCount": 21,
            "subbedCount": 21,
            "dubbedCount": 17,
            "description": "Uryuu Kamihate is a high school student striving to enter Kyoto University\u2019s medical school. After being raised at an orphanage, Uryuu is taken in by the chief priest at Amagami Shrine, where he begins to live as a freeloader\u2014and to cohabit with Yae, Yuna, and Asahi, the three beautiful shrine maiden sisters! What\u2019s more, the condition he must meet in order to live at the shrine for free is to marry into the family and inherit the shrine! How will Uryuu overcome his marriage meetings with the three sisters as well as the many challenges that Amagami Shrine faces? So begins a miraculous rom-com about living under the same roof with three shrine maidens!<br>\n<br>\n(Source: Crunchyroll, edited)",
            "url": "/watch/675c236b0027b1bff29c/21"
        },
    ],
    "topAired": [
        {
            "id": "67759a9c00231b0dea36",
            "english": "Unnamed Memory Season 2",
            "romaji": "Unnamed Memory Act.2",
            "native": "Unnamed Memory Act.2",
            "ageRating": "PG-13",
            "malScore": 7.15,
            "averageScore": 68,
            "duration": 24,
            "genres": [
                "Adventure",
                "Fantasy",
                "Romance"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/large/bx178550-1mjYHtOwiqkC.jpg",
            "banner": "https://s4.anilist.co/file/anilistcdn/media/anime/banner/178550-iM5NTASgQ4wt.jpg",
            "season": "WINTER",
            "startDate": "Jan 12, 2025",
            "status": "RELEASING",
            "synonyms": [
                "Unnamed Memory \u7b2c2\u671f",
                "Unnamed Memory 2nd Season",
                "\u30a2\u30f3\u30cd\u30fc\u30e0\u30c9\u30e1\u30e2\u30ea\u30fc Act.2"
            ],
            "type": "TV",
            "year": 2025,
            "epCount": 9,
            "subbedCount": 9,
            "dubbedCount": 0,
            "description": "The second season of <i>Unnamed Memory</i>.<br>\n<br>\nSeeking to end a curse thwarting his lineage, Prince Oscar sets out on a quest that leads him to a powerful and beautiful witch, Tinasha, and he demands a unique bargain: marriage. Though unenthused by the proposal, she agrees to stay in his castle for a year while researching the spell cast upon him. But beneath her beauty lies a lifetime of dark secrets that soon come to light.<br>\n<br>\n(Source: Crunchyroll)"
        },
        {
            "id": "675c236b0027b1bff29c",
            "english": "Tying the Knot with an Amagami Sister",
            "romaji": "Amagami-san Chi no Enmusubi",
            "native": "\u7518\u795e\u3055\u3093\u3061\u306e\u7e01\u7d50\u3073",
            "ageRating": "PG-13",
            "malScore": 7.16,
            "averageScore": 69,
            "duration": 24,
            "genres": [
                "Comedy",
                "Drama",
                "Ecchi",
                "Romance",
                "Supernatural"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/large/bx164172-GY2aqItIuqtR.jpg",
            "banner": "https://s4.anilist.co/file/anilistcdn/media/anime/banner/164172-ceuofxXerReI.jpg",
            "season": "FALL",
            "startDate": "Jan 12, 2025",
            "status": "RELEASING",
            "synonyms": [
                "Matchmaking of the Amagami Household",
                "\u0e14\u0e49\u0e32\u0e22\u0e41\u0e14\u0e07\u0e1c\u0e39\u0e01\u0e23\u0e31\u0e01\u0e1a\u0e49\u0e32\u0e19\u0e2d\u0e32\u0e21\u0e32\u0e01\u0e32\u0e21\u0e34",
                "\u7d50\u7de3\u7518\u795e\u795e\u793e",
                "\u7518\u795e\u5bb6\u7684\u8fde\u7406\u679d",
                "\u0631\u0628\u0637 \u0627\u0644\u0639\u0642\u062f \u0645\u0639 \u0623\u062e\u0648\u0627\u062a \u0623\u0645\u0627\u063a\u0627\u0645\u064a"
            ],
            "type": "TV",
            "year": 2024,
            "epCount": 21,
            "subbedCount": 21,
            "dubbedCount": 17,
            "description": "Uryuu Kamihate is a high school student striving to enter Kyoto University\u2019s medical school. After being raised at an orphanage, Uryuu is taken in by the chief priest at Amagami Shrine, where he begins to live as a freeloader\u2014and to cohabit with Yae, Yuna, and Asahi, the three beautiful shrine maiden sisters! What\u2019s more, the condition he must meet in order to live at the shrine for free is to marry into the family and inherit the shrine! How will Uryuu overcome his marriage meetings with the three sisters as well as the many challenges that Amagami Shrine faces? So begins a miraculous rom-com about living under the same roof with three shrine maidens!<br>\n<br>\n(Source: Crunchyroll, edited)"
        },
    ],
    "topUpcoming": [
        {
            "id": "6774772800330ef06e8a",
            "english": "Fate/strange Fake",
            "romaji": "Fate/strange Fake",
            "native": "Fate/strange Fake",
            "ageRating": "PG-13",
            "malScore": null,
            "averageScore": null,
            "duration": 25,
            "genres": [
                "Action",
                "Adventure",
                "Fantasy",
                "Mystery",
                "Supernatural"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/large/bx166617-34fpC9y47tTx.png",
            "banner": "https://s4.anilist.co/file/anilistcdn/media/anime/banner/166617-P4w3p0H4lE1O.jpg",
            "season": null,
            "startDate": null,
            "status": "NOT_YET_RELEASED",
            "synonyms": [],
            "type": "TV",
            "year": null,
            "epCount": 1,
            "subbedCount": 1,
            "dubbedCount": 0,
            "description": "In a Holy Grail War, Mages (Masters) and their Heroic Spirits (Servants) fight for the control of the Holy Grail\u2014an omnipotent wish-granting device said to fulfill any desire. Years have passed since the end of the Fifth Holy Grail War in Japan. Now, signs portend the emergence of a new Holy Grail in the western American city of Snowfield. Sure enough, Masters and Servants begin to gather... <br><br>\n\nA missing Servant class...<br>\nImpossible Servant summonings...<br>\nA nation shrouded in secrecy...<br>\nAnd a city created as a battleground.<br>\n<br>\nIn the face of such irregularities, the Holy Grail War is twisted and driven into the depth of madness. Let the curtain rise on a masquerade of humans and heroes, made to dance upon the stage of a false Holy Grail. <i>This is a Holy Grail War covered in lies.</i>\n<br><br>\n(Source: Official Site, Aniplex USA, edited)\n<br><br>\n<i>Notes:</i><br>\n\u2022  <i>Special premiere of Episode 1 in its English Dub occurred in Los Angeles at the Fate 20th Anniversary Showcase event and as well through Crunchyroll\u2019s YouTube Channel on November 23, 2024 before the Japanese television premiere.</i><br>\n\u2022  <i>The Japanese advanced premiere occurred during the \"Fate New Year's Eve TV Special 2024\" on December 31, 2024.</i>"
        },
        {
            "id": "67759a9c001bcb01cfab",
            "english": "Hell\u2019s Paradise Season 2",
            "romaji": "Jigokuraku 2nd Season",
            "native": "\u5730\u7344\u697d \u7b2c\u4e8c\u671f",
            "ageRating": null,
            "malScore": null,
            "averageScore": null,
            "duration": null,
            "genres": [
                "Action",
                "Adventure",
                "Mystery",
                "Supernatural"
            ],
            "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/large/bx166613-YzuAjRNJKo1K.png",
            "banner": "https://s4.anilist.co/file/anilistcdn/media/anime/banner/166613-drS86exJlIjG.jpg",
            "season": "WINTER",
            "startDate": null,
            "status": "NOT_YET_RELEASED",
            "synonyms": [
                "Hell\u2019s Paradise: Jigokuraku Season 2",
                "\u0e2a\u0e38\u0e02\u0e32\u0e27\u0e14\u0e35\u0e2d\u0e40\u0e27\u0e08\u0e35",
                "\u0410\u0434\u0441\u043a\u0438\u0439 \u0440\u0430\u0439"
            ],
            "type": "TV",
            "year": 2026,
            "epCount": 0,
            "subbedCount": 0,
            "dubbedCount": 0,
            "description": "The second season of <i>Jigokuraku</i>."
        },
    ],
    "userInfo": {
        "userId": "123rff3e23",
        "username": "test",
        "email": "test@gmail.com"
    },
    "ctotal": 0//User's Continue Watchling list 
}
```

### 2. Anime Information
- **URL:** `https://kuudere.to/anime/{anime_id}`
- **Method:** POST

#### Required Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | `string` | Yes | Authentication key |
| `secret` | `string` | Yes | Authentication secret |

#### URL Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `anime_id` | `string` | Yes | Unique identifier for the anime |

#### Sample Response
```json
{
    "data": {
        "id": "67759a9c00231b0dea36",
        "english": "Unnamed Memory Season 2",
        "romaji": "Unnamed Memory Act.2",
        "native": "Unnamed Memory Act.2",
        "ageRating": "PG-13",
        "malScore": 7.15,
        "averageScore": 68,
        "duration": 24,
        "genres": [
            "Adventure",
            "Fantasy",
            "Romance"
        ],
        "cover": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/medium/bx178550-1mjYHtOwiqkC.jpg",
        "banner": "https://s4.anilist.co/file/anilistcdn/media/anime/banner/178550-iM5NTASgQ4wt.jpg",
        "season": "WINTER",
        "startDate": "2025-01-07T00:00:00.000+00:00",
        "status": "RELEASING",
        "synonyms": [
            "Unnamed Memory \u7b2c2\u671f",
            "Unnamed Memory 2nd Season",
            "\u30a2\u30f3\u30cd\u30fc\u30e0\u30c9\u30e1\u30e2\u30ea\u30fc Act.2"
        ],
        "studios": [
            "ENGI",
            "KADOKAWA",
            "Tencent",
            "Sammy",
            "AT-X",
            "Bandai Namco Music Live"
        ],
        "type": "TV",
        "year": 2025,
        "epCount": 9,
        "subbedCount": 9,
        "dubbedCount": 0,
        "description": "The second season of <i>Unnamed Memory</i>.<br>\n<br>\nSeeking to end a curse thwarting his lineage, Prince Oscar sets out on a quest that leads him to a powerful and beautiful witch, Tinasha, and he demands a unique bargain: marriage. Though unenthused by the proposal, she agrees to stay in his castle for a year while researching the spell cast upon him. But beneath her beauty lies a lifetime of dark secrets that soon come to light.<br>\n<br>\n(Source: Crunchyroll)",
        "in_watchlist": false,
        "folder": null,//watchlist folder
        "views": "150 Views",
        "likes": "0 Likes"
    },
    "userInfo": {
        "userId": "1234",
        "username": "test",
        "email": "test@gmail.com"
    },
    "success": true
}
```

### 3. Anime Streaming Information
- **URL:** `https://kuudere.to/watch/{anime_id}/{episode_number}`
- **Method:** POST

#### Required Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | `string` | Yes | Authentication key |
| `secret` | `string` | Yes | Authentication secret |

#### URL Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `anime_id` | `string` | Yes | Unique identifier for the anime |
| `episode_number` | `integer` | Yes | Specific episode to stream |

#### Sample Response
```json
{
    "all_episodes": [
        {
            "id": "677d62ed001b25ef0fe7",
            "titles": [
                "Episode 1"
            ],
            "filler": null,
            "number": 1,
            "recap": null,
            "aired": "Jan 07, 2025",
            "ago": "1 month ago"
        },
        {
            "id": "678695c4001399460c77",
            "titles": [
                "Episode 2"
            ],
            "filler": null,
            "number": 2,
            "recap": null,
            "aired": "Jan 14, 2025",
            "ago": "1 month ago"
        },
    ],
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
    "episode_comments": [],
    "total_comments": 0,
    "episode_id": "677d62ed001b25ef0fe7",
    "success": true,
    "duration": 0,
    "current": 0,
    "intro_start": 0,
    "intro_end": 0,
    "outro_start": 0,
    "outro_end": 0
}
```

## Example Usage

- Python

```python
import requests

def get_anime_info(anime_id, key, secret):
    url = f"https://kuudere.to/anime/{anime_id}"
    payload = {
        "key": key,
        "secret": secret
    }
    response = requests.post(url, json=payload)
    return response.json()
```
- Curl

```sh
curl 'https://kuudere.to/home' \
  -H 'accept: */*' \
  -H 'accept-language: en-US,en;q=0.8' \
  -H 'content-type: application/json' \
  -H 'sec-gpc: 1' \
  -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36' \
  --data-raw '{"key":"#####, "secret": "######"}'

```
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

