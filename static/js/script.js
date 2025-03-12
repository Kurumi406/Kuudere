// WATCH PAGE COMPONENTS =======================================================

// Anime Player Component
function animePlayer(config) {
    const prefData = localStorage.getItem("pref");
    let useDisqus = false;
    let AutoNext = false;
    let AutoSkipOutro = false;
    let AutoSkipIntro = false;
    let AutoPlay = false;
    
    if (prefData) {
        const storedData = JSON.parse(prefData);
        const currentTime = new Date().getTime();
    
        if (storedData.expiration && currentTime < storedData.expiration) {
            const settingsData = storedData.value;
    
            useDisqus = false;


            AutoNext = settingsData.autoNext
            AutoSkipIntro = settingsData.autoSkipIntro
            AutoSkipOutro = settingsData.autoSkipOutro
            AutoPlay = settingsData.autoPlay
    
            let defaultLang = settingsData.defaultLang;
            
        } else {
            console.log("Stored data has expired.");
            localStorage.removeItem("pref");
        }
    }    
    return {
        // Initialize with passed config
        mainContentHeight: 0,
        userInfo: typeof config.userInfo === 'string' ? JSON.parse(config.userInfo) : config.userInfo,
        animeId: config.animeId,
        currentEpisode: config.epNumber,
        animeInfo: {},
        allEpisodes: [],
        episodeLinks: [],
        comments: [],
        currentServer: null,
        editModalOpen: false,
        editLoading: false,
        editEpisodeData: {},
        editErrors: [],
        currentVideoLink: '',
        isLoading: false,
        isVideoLoading: false,
        isCommentsLoading: false,
        isLoadingMore: false,
        currentPage: 1,
        hasMoreComments: true,
        visibleComments: 5, // Number of initially visible comments
        commentsPerLoad: 5, // Number of comments to load each time
        searchInput: '',
        newComment: '',
        isSpoiler: false,
        showEmojiPicker: false,
        total_comments: 0,
        isShareOpen: false,
        url: window.location.href + (config.userInfo ? `?ref=${(typeof config.userInfo === 'string' ? JSON.parse(config.userInfo) : config.userInfo).userId}` : ''),        
        title: '',
        description: `Dude Check It Out They Added Episode ${config.epNumber}`,
        copySuccess: false,
        useDisqus,
        unique: '',
        uniqueUrll: '',
        playerDuration: 0,
        currentPlaybackTime: 0,
        hasEnded: false,
        checkInterval: null,
        saveInterval: null,
        currentEpisodeId: null,
        playerStatusz: null,
        watchedDuraion: null,
        sent: null,
        IsOutroPlaying: false,
        IsIntroPlaying: false,
        outro_end: 0,
        intro_start: 0,
        intro_end: 0,
        outro_start: 0,
        AutoNext,
        AutoSkipIntro,
        AutoSkipOutro,
        AutoPlay,
        pausedOnStart: null,
        isEditModalOpen: false,
        isUpdating: false,
        isPostingComment: false,
        editData: {
            id: null,
            title: '',
            romaji_title: '',
            native_title: '',
            intro_start: 0,
            intro_end: 0,
            outro_start: 0,
            outro_end: 0
        },

        // In the animePlayer() component
        openEpisodeEdit(episode) {
            if(!this.userInfo){
                window.dispatchEvent(new CustomEvent('trigger-auth-modal'));
                return;
            } 
            this.isEditModalOpen = true;
            this.editData = {
                id: episode.id,
                id: episode.id,
                title: episode.titles[0] ?? '', // Handle null values
                romaji_title: episode.titles[1] ?? '',
                native_title: episode.titles[2] ?? '',
                intro_start: parseInt(this.intro_start) || 0, // Convert string to number
                intro_end: parseInt(this.intro_end) || 0,
                outro_start: parseInt(this.outro_start) || 0,
                outro_end: parseInt(this.outro_end) || 0        
            };
            
            // If you need to convert timestamps
            // Example: if times are stored as MM:SS strings
            const convertTime = (time) => {
                if (typeof time === 'string') {
                    const [minutes, seconds] = time.split(':');
                    return parseInt(minutes) * 60 + parseInt(seconds);
                }
                return time;
            };

            // Use this if your times need conversion
            this.editData.intro_start = convertTime(this.intro_start);
            this.editData.intro_end = convertTime(this.intro_end);
            this.editData.outro_start = convertTime(this.outro_start);
            this.editData.outro_end = convertTime(this.outro_end);
        },

        async submitEpisodeUpdate() {
            this.isUpdating = true;
            try {
                const response = await fetch(`/update/episode/${this.editData.id}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(this.editData)
                });

                if (!response.ok){ 
                    window.dispatchEvent(new CustomEvent('notify', {
                        detail: { message: 'This Feature Currently Unavailable', type: 'error' }
                    }));
                    throw new Error('Update failed');
                }
                
                // Update local data
                const episode = this.allEpisodes.find(e => e.id === this.editData.id);
                if (episode) {
                    episode.titles = [
                        this.editData.title,
                        this.editData.romaji_title,
                        this.editData.native_title
                    ];
                    episode.intro_start = this.editData.intro_start;
                    episode.intro_end = this.editData.intro_end;
                    episode.outro_start = this.editData.outro_start;
                    episode.outro_end = this.editData.outro_end;
                }

                anime({
                    targets: '.episode',
                    scale: [0.95, 1],
                    duration: 500,
                    easing: 'easeOutElastic(1, .5)'
                });

                this.isEditModalOpen = false;
            } catch (error) {
                console.error('Update error:', error);
            } finally {
                this.isUpdating = false;
            }
        },

        // Initialize the player
        init() {
            this.setupHeightCalculation();
            this.initEmojiPicker();
            this.fetchPlayerData();
            this.skipIntro();
            this.skipOutro();
        },

        setupHeightCalculation() {
            // Function to calculate and set heights
            const updateHeights = () => {
              // Get the main content element
              const mainContent = document.querySelector('.main-content');
              if (!mainContent) return;
              
              // Calculate its height
              this.mainContentHeight = mainContent.offsetHeight;
              
              // Log for debugging
              console.log('Main content height updated:', this.mainContentHeight);
            };
            
            // Initial calculation after DOM is loaded
            this.$nextTick(() => {
              // Wait a bit for everything to render properly
              setTimeout(updateHeights, 100);
            });
            
            // Update when window is resized
            window.addEventListener('resize', updateHeights);
            
            // Update when video is loaded (which might change the height)
            document.addEventListener('videoLoaded', updateHeights);
          },

        fetchPlayerData(limk){
            if (limk !== undefined){
            console.log(limk)
            const player = document.getElementById('playerIframeId');
            const playerOrigin = new URL(player.src).origin;
            // Initialize properties and logic

                window.addEventListener('message', (e) => {
                    if (e.origin !== this.playerOrigin) return;

                    // Handle current time
                    if (e.data.currentTime !== undefined) {
                        console.log(e.data.currentTime);
                        this.currentPlaybackTime = e.data.currentTime;
                    }
                    // Handle duration
                    if (e.data.duration !== undefined) {
                        console.log(e.data.duration);
                        this.playerDuration = e.data.duration;
                    }
                    this.checkVideoCompletion();
                });
            }
        },

        // Skip Intro Functionality
        skipIntro() {
            const iframe = this.$refs.videoPlayer;
            if (!iframe || !iframe.contentWindow) return;

            const playerOrigin = new URL(iframe.src).origin;
            iframe.contentWindow.postMessage({ 
                command: 'seek', 
                value: this.intro_end 
            }, playerOrigin);

            this.IsIntroPlaying = false;
        },

        // Skip Outro Functionality
        skipOutro() {
            const iframe = this.$refs.videoPlayer;
            if (!iframe || !iframe.contentWindow) return;

            const playerOrigin = new URL(iframe.src).origin;
            iframe.contentWindow.postMessage({
                command: 'seek',
                value: this.outro_end
            }, playerOrigin);

            this.IsOutroPlaying = false;
        },

        toggleEmojiPicker() {
            this.showEmojiPicker = !this.showEmojiPicker;
        },

        async fetchInitialData() {
            try {
                await this.fetchEpisodeData(this.currentEpisode);
            } catch (error) {
                console.error('Initial data fetch failed:', error);
            }
        },

        async fetchEpisodeData(episodeNumber) {
            this.isLoading = true;

            try {
                // URL parameter logic
                const urlParams = new URLSearchParams(window.location.search);
                const serverName = urlParams.get('server');
                const lang = urlParams.get('lang');  // Get the `lang` parameter from the URL
                history.pushState(null, '', `/watch/${this.animeId}/${episodeNumber}?server=${serverName}&lang=${lang}`);

                // Fetch data for the episode
                const response = await fetch(`/watch-api/${this.animeId}/${episodeNumber}`);
                const data = await response.json();
                this.unique = `/watch/${this.animeId}/${episodeNumber}`;
                this.uniqueUrll = `https://kuudere.to/watch/${this.animeId}/${episodeNumber}`;

                this.animeInfo = data.anime_info || {};
                this.allEpisodes = (data.all_episodes || []).sort((a, b) => a.number - b.number);
                this.episodeLinks = data.episode_links || []
                this.currentEpisode = episodeNumber;
                this.outro_end = parseFloat(data.outro_end) || 0;
                this.intro_start = parseFloat(data.intro_start) || 0;
                this.intro_end = parseFloat(data.intro_end) || 0;
                this.outro_start = parseFloat(data.outro_start) || 0;
                this.currentEpisodeId = data.episode_id; 
                this.total_comments = data.total_comments;
                this.watchedDuraion = data.current;
                this.sent = null,
                this.pausedOnStart = null,
                document.getElementById('epn').innerText = episodeNumber;

                // Try to find a server based on `serverName` from the URL
                let selectedServer = null;

                // If a server is specified, look for it
                if (serverName && lang) {
                    selectedServer = this.episodeLinks.find(link => link.serverName === serverName && link.dataType === lang);
                }

                // Helper function to retrieve valid localStorage data
                function getValidLocalStorageItem(key) {
                    const item = localStorage.getItem(key);
                    if (!item) return null;

                    const parsedItem = JSON.parse(item);
                    const currentTime = new Date().getTime();

                    if (parsedItem.expiration && currentTime < parsedItem.expiration) {
                        return parsedItem.value;
                    } else {
                        localStorage.removeItem(key);
                        return null;
                    }
                }

                const defaultServer = getValidLocalStorageItem('defaultServer');
                const defaultLang = getValidLocalStorageItem('defaultLang');

                if (!selectedServer && defaultServer && lang) {
                    selectedServer = this.episodeLinks.find(link => 
                        link.serverName === defaultServer && link.dataType === lang
                    );
                }

                // Check for default lang with explicit serverName
                if (!selectedServer && defaultLang && serverName) {
                    selectedServer = this.episodeLinks.find(link => 
                        link.serverName === serverName && link.dataType === defaultLang
                    );
                }

                // Check for default server and default lang
                if (!selectedServer && defaultServer && defaultLang) {
                    selectedServer = this.episodeLinks.find(link => 
                        link.serverName === defaultServer && link.dataType === defaultLang
                    );
                }

                // Fallback to 'dub' or first available link
                if (!selectedServer) {
                    selectedServer = this.episodeLinks.find(link => link.dataType === 'dub') || this.episodeLinks[0];
                }

                // Select the determined server
                if (selectedServer) {
                    this.selectServer(selectedServer);
                } else {
                    this.currentVideoLink = '';
                }

                this.fetchComments(episodeNumber)
                
            } catch (error) {
                console.error('Error fetching episode data:', error);
                this.animeInfo = {};
                this.allEpisodes = [];
                this.episodeLinks = [];
                this.currentVideoLink = '';
                this.watchedDuraion = null;
                this.outro_end = 0;
                this.intro_start = 0;
                this.intro_end = 0;
                this.outro_start = 0;
            } finally {
                this.isLoading = false;
                this.$nextTick(() => {
                const container = this.$refs.episodesContainer;
                const episodeElement = this.$el.querySelector(`[data-episode="${this.currentEpisode}"]`);
                
                if (container && episodeElement) {
                    // Calculate position with smooth scroll
                    const elementTop = episodeElement.offsetTop - container.offsetTop;
                    container.scrollTo({
                    top: elementTop - (container.clientHeight / 2),
                    behavior: 'smooth'
                    });
                }
                });
            }
        },

        async fetchComments(episodeNumber, page = 1) {
            this.isCommentsLoading = true;
            let url = `/api/anime/comments/${this.animeId}/${episodeNumber}?page=${page}`;
            
            try {
                const response = await fetch(url);
                const data = await response.json();
                
                if (page === 1) {
                    this.comments = data.comments.map(comment => ({
                        ...comment,
                        showReplyForm: false,
                        showReplies: false,
                        replyContent: '',
                        isPostingReply: false
                    }));
                    this.visibleComments = Math.min(this.comments.length, this.commentsPerLoad);
                } else {
                    const newComments = data.comments.map(comment => ({
                        ...comment,
                        showReplyForm: false,
                        showReplies: false,
                        replyContent: '',
                        isPostingReply: false
                    }));
                    this.comments = [...this.comments, ...newComments];
                    this.visibleComments = Math.min(this.comments.length, this.visibleComments + this.commentsPerLoad);
                }
                
                this.currentPage = page;
                this.hasMoreComments = data.has_more;
                this.total_comments = data.total_comments || this.comments.length;
            } catch (error) {
                console.error('Error fetching comments:', error);
                // Handle error appropriately
            } finally {
                this.isCommentsLoading = false;
            }
        },

        // New method for loading more comments
        loadMoreComments() {
            if (this.isLoadingMore) return;
        
            this.isLoadingMore = true;
        
            if (this.visibleComments < this.comments.length) {
                // Load more from existing comments
                this.visibleComments = Math.min(this.visibleComments + this.commentsPerLoad, this.comments.length);
                this.isLoadingMore = false;
            } else if (this.hasMoreComments) {
                // Fetch more comments from the server
                const nextPage = this.currentPage + 1;
                this.fetchComments(this.currentEpisode, nextPage)
                    .finally(() => {
                        this.isLoadingMore = false;
                    });
            } else {
                this.isLoadingMore = false;
            }
        },

        switchToBuiltIn() {
            this.useDisqus = false;
            this.animateSwitch('left');
        },
        
        
        selectServer(server) {
            this.isVideoLoading = true;
            this.currentServer = server;
            this.currentVideoLink = server.dataLink;
            this.fetchPlayerData(this.currentVideoLink);

            // Clear existing intervals and listeners
            if (this.seekInterval) clearInterval(this.seekInterval);
            if (this.timeUpdateInterval) clearInterval(this.timeUpdateInterval);
            if (this.messageHandler) window.removeEventListener('message', this.messageHandler);

            const iframe = this.$refs.videoPlayer;
            if (iframe) {
                let playerOrigin;
                try {
                    playerOrigin = new URL(this.currentVideoLink).origin;
                } catch (error) {
                    console.error('Invalid video URL:', this.currentVideoLink);
                    this.isVideoLoading = false;
                    return;
                }

                // Add API parameter with proper encoding
                const apiParam = `api=${encodeURIComponent(window.location.hostname)}`;
                iframe.src = this.currentVideoLink.includes('?') 
                    ? `${this.currentVideoLink}&${apiParam}`
                    : `${this.currentVideoLink}?${apiParam}`;

                // Message handler with enhanced logging
                this.messageHandler = (e) => {

                    // Log ALL incoming data
                    console.groupCollapsed('[Parent] Received player message');
                    console.log('Full message data:', e.data);
                    
                    // Handle different response types
                    if (e.data.playerStatus === 'Ready') {
                        console.log('🔵 Player Ready | Duration:', e.data.duration);
                    }

                    if (e.data.currentTime !== undefined) {
                        console.log('⏱ Current Time:', e.data.currentTime);
                        this.currentPlaybackTime = e.data.currentTime;

                        if (this.watchedDuraion != null && this.playerDuration !== null && this.sent == null){
                            iframe.contentWindow.postMessage({ command: 'seek', value: this.watchedDuraion }, playerOrigin);
                            this.sent = true;
                        }

                        // Inside the messageHandler(e) function
                        if (e.data.currentTime !== undefined) {
                            // Replace the existing logic for pausedOnStart with:
                            if (!this.AutoPlay && this.pausedOnStart === null) {
                                iframe.contentWindow.postMessage({ command: 'pause' }, playerOrigin);
                                this.pausedOnStart = true;
                            }
                        }

                        if (this.intro_end !== 0 && this.currentPlaybackTime >= this.intro_start && this.currentPlaybackTime <= this.intro_end) {
                            console.log('introPlaying')
                            this.IsIntroPlaying = true;
                            if (this.AutoSkipIntro == true){
                                this.skipIntro()
                            }
                        }else{
                            this.IsIntroPlaying = false
                        }

                        if (this.outro_end !== 0 && this.outro_start && this.currentPlaybackTime >= this.outro_start && this.currentPlaybackTime <= this.outro_end) {
                            console.log('OutroPlaying')
                            this.IsOutroPlaying = true;
                            if (this.AutoSkipOutro == true){
                                this.skipOutro()
                            }
                        }else{
                            this.IsOutroPlaying = false
                        }
                    }

                    if (e.data.duration !== undefined) {
                        console.log('📏 Duration:', e.data.duration);
                        this.playerDuration = e.data.duration;
                    }

                    this.playerStatusz =  e.data.playerStatus;
                    if (e.data.playerStatus === 'Playing' || e.data.playerStatus === 'Paused') {
                        console.log('🎬 Status:', e.data.playerStatus);
                        this.playerState = e.data.playerStatus;
                    }

                    console.groupEnd();
                };

                window.addEventListener('message', this.messageHandler);

                // Iframe load handlers
                iframe.onload = () => {
                    this.isVideoLoading = false;
                    console.log('🚀 Iframe loaded');
                    
                    // Start polling for updates
                    this.timeUpdateInterval = setInterval(() => {
                        iframe.contentWindow.postMessage({ command: 'getTime' }, playerOrigin);
                        iframe.contentWindow.postMessage({ command: 'getStatus' }, playerOrigin);
                    }, 100); // Update every second
                };

                // Fallback timeout
                setTimeout(() => {
                    if (this.isVideoLoading) {
                        this.isVideoLoading = false;
                        console.warn('⌛ Player load timeout');
                    }
                }, 10000);
            }

            // History and storage updates
            const lang = server.dataType === 'sub' ? 'sub' : server.dataType === 'dub' ? 'dub' : '';
            const urlParams = new URLSearchParams(window.location.search);
            urlParams.set('server', server.serverName);
            lang ? urlParams.set('lang', lang) : urlParams.delete('lang');
            history.replaceState(null, '', `${window.location.pathname}?${urlParams.toString()}`);

            // Helper function to set localStorage with expiration
            function setLocalStorageItem(key, value, days = 356) {
                const expirationTime = new Date().getTime() + days * 24 * 60 * 60 * 1000;
                const dataWithExpiration = {
                    value,
                    expiration: expirationTime
                };
                localStorage.setItem(key, JSON.stringify(dataWithExpiration));
            }

            if (server.serverName) setLocalStorageItem('defaultServer', server.serverName);
            if (server.dataType) setLocalStorageItem('defaultLang', server.dataType);


            if (this.checkInterval) clearInterval(this.checkInterval);
            
            // Set up new interval check
            this.checkInterval = setInterval(() => {
                if (this.playerDuration > 0 && this.currentPlaybackTime > 0) {
                this.checkVideoCompletion();
                }
            }, 1000); // Check every second
            this.saveInterval = setInterval(() => {
                    this.saveProgress();
                }, 10000); // Save progress every 10 seconds
        },
        // In the animePlayer() component:
        async selectEpisode(episodeNumber) {
            // 1. Reset all player-related states FIRST
            this.hasEnded = false;
            this.playerDuration = 0;
            this.currentPlaybackTime = 0;
            this.IsOutroPlaying = false;
            this.IsIntroPlaying = false;
            this.outro_end = 0;
            this.intro_end = 0;
            this.outro_start = 0;
            this.intro_start = 0;
            this.sent = null;
            this.pausedOnStart = null;
            
            // 2. Clean up previous iframe listeners and intervals
            if (this.messageHandler) {
                window.removeEventListener('message', this.messageHandler);
                this.messageHandler = null;
            }
            if (this.timeUpdateInterval) clearInterval(this.timeUpdateInterval);
            if (this.checkInterval) clearInterval(this.checkInterval);
            if (this.saveInterval) clearInterval(this.saveInterval);

            // 3. Force iframe unload before loading new episode
            this.currentVideoLink = ''; // Unload iframe
            await this.$nextTick(); // Wait for DOM update

            // 4. Now load new episode data
            await this.fetchEpisodeData(episodeNumber);
            
            // 5. Add slight delay before initializing new player tracking
            setTimeout(() => {
                const iframe = this.$refs.videoPlayer;
                if (iframe) {
                    // 6. Reset and reinitialize time checks
                    this.checkInterval = setInterval(() => {
                        if (this.playerDuration > 0 && this.currentPlaybackTime > 0) {
                            // Update intro/outro visibility with new episode's timing data
                            this.IsIntroPlaying = this.currentPlaybackTime >= this.intro_start && 
                                            this.currentPlaybackTime <= this.intro_end;
                            this.IsOutroPlaying = this.currentPlaybackTime >= this.outro_start && 
                                                this.currentPlaybackTime <= this.outro_end;
                        }
                    }, 100);

                    // 7. Reinitialize player tracking
                    iframe.onload = () => {
                        this.isVideoLoading = false;
                        this.initPlayerTracking(iframe);
                        
                        // 8. Restart save progress interval
                        this.saveInterval = setInterval(() => {
                            this.saveProgress();
                        }, 10000);
                    };
                }
            }, 300);

            // 9. Scroll to current episode in list
            this.$nextTick(() => {
                const container = this.$refs.episodesContainer;
                const episodeElement = this.$el.querySelector(`[data-episode="${this.currentEpisode}"]`);
                
                if (container && episodeElement) {
                    const elementTop = episodeElement.offsetTop - container.offsetTop;
                    container.scrollTo({
                        top: elementTop - (container.clientHeight / 2),
                        behavior: 'smooth'
                    });
                }
            });
        },

        initPlayerTracking(iframe) {
            // 1. Clean previous intervals
            if (this.timeUpdateInterval) clearInterval(this.timeUpdateInterval);
            if (this.statusInterval) clearInterval(this.statusInterval);

            // 2. Store reference to current iframe
            this.currentIframe = iframe;
            
            try {
                // 3. Get origin of NEW iframe
                this.playerOrigin = new URL(iframe.src).origin;
            } catch (error) {
                console.error('Invalid iframe URL:', iframe.src);
                return;
            }

            // 4. Remove previous message handler if exists
            if (this.messageHandler) {
                window.removeEventListener('message', this.messageHandler);
            }

            // 5. New message handler with origin and source validation
            this.messageHandler = (e) => {
                // 5a. Verify message origin
                if (e.origin !== this.playerOrigin) {
                    console.warn(`Blocked message from unauthorized origin: ${e.origin}`);
                    return;
                }

                // 5b. Verify message came from CURRENT iframe
                if (e.source !== iframe.contentWindow) {
                    console.warn('Blocked message from previous iframe instance');
                    return;
                }

                // 5c. Handle message types
                console.groupCollapsed('[Player Message]', new Date().toISOString());
                
                // Handle current time updates
                if (e.data.currentTime !== undefined) {
                    this.currentPlaybackTime = e.data.currentTime;
                    console.log('⏱ Current Time:', this.currentPlaybackTime);
                }

                // Handle duration updates
                if (e.data.duration !== undefined) {
                    this.playerDuration = e.data.duration;
                    console.log('📏 Duration:', this.playerDuration);
                }

                // Handle player state changes
                if (e.data.playerStatus) {
                    this.playerStatusz =  e.data.playerStatus;
                    console.log('🎬 Player Status:', e.data.playerStatus);
                    switch (e.data.playerStatus) {
                        case 'ended':
                            this.handleVideoEnd();
                            break;
                        case 'playing':
                        case 'paused':
                            this.playerState = e.data.playerStatus;
                            break;
                    }
                }

                console.groupEnd();
            };

            // 6. Attach fresh listener
            window.addEventListener('message', this.messageHandler);

            // 7. Initialize polling with safety checks
            this.timeUpdateInterval = setInterval(() => {
                if (!iframe.contentWindow || iframe.contentWindow.closed) {
                    clearInterval(this.timeUpdateInterval);
                    return;
                }
                
                try {
                    iframe.contentWindow.postMessage({ command: 'getTime' }, this.playerOrigin);
                    iframe.contentWindow.postMessage({ command: 'getStatus' }, this.playerOrigin);
                } catch (error) {
                    console.error('PostMessage error:', error);
                    clearInterval(this.timeUpdateInterval);
                }
            }, 1000);

            // 8. Add unload handler
            iframe.addEventListener('load', () => {
                console.log('🔄 Iframe reload detected - cleaning up');
                this.cleanupPlayerTracking();
            });
        },

        skipIntro() {
            const iframe = this.$refs.videoPlayer;
            if (!iframe || !iframe.contentWindow) return;
            
            // Get current iframe origin
            const playerOrigin = new URL(iframe.src).origin;
            
            // Seek to end of intro
            iframe.contentWindow.postMessage({ 
                command: 'seek', 
                value: this.intro_end 
            }, playerOrigin);
            
            // Hide intro button after skip
            this.IsIntroPlaying = false;
        },

        skipOutro() {
            const iframe = this.$refs.videoPlayer;
            if (!iframe || !iframe.contentWindow) return;

            // Get current iframe origin
            const playerOrigin = new URL(iframe.src).origin;
            
            // Seek to end of outro
            iframe.contentWindow.postMessage({
                command: 'seek',
                value: this.outro_end
            }, playerOrigin);

            // Hide outro button after skip
            this.IsOutroPlaying = false;
        },


        // 9. Cleanup method
        cleanupPlayerTracking() {
            if (this.timeUpdateInterval) clearInterval(this.timeUpdateInterval);
            if (this.statusInterval) clearInterval(this.statusInterval);
            if (this.messageHandler) {
                window.removeEventListener('message', this.messageHandler);
            }
            this.playerDuration = 0;
            this.currentPlaybackTime = 0;
            if (this.saveInterval) clearInterval(this.saveInterval);
        },

        // 10. Modified video end handler
        handleVideoEnd() {
            if (this.hasEnded) return;
            
            console.log('🎬 Video ended - checking for next episode');
            this.hasEnded = true;
            
            // Small delay before loading next episode
            setTimeout(() => {
                this.loadNextEpisode();
            }, 1500);
        },

        checkVideoCompletion() {
            // Consider video completed if within 1 second of end
            if (!this.isVideoLoading && this.currentVideoLink != this.$refs.videoPlayer){
                const completionThreshold = 1; 
                const timeRemaining = this.playerDuration - this.currentPlaybackTime;
                
                if (this.playerDuration > 0 && 
                    timeRemaining <= completionThreshold && 
                    !this.hasEnded) {
                    this.hasEnded = true;
                    this.loadNextEpisode();
                }
            }
        },

        loadNextEpisode() {
            if (this.AutoNext == true){
                const currentIndex = this.allEpisodes.findIndex(ep => ep.number === this.currentEpisode);
            
                if (currentIndex > -1 && currentIndex + 1 < this.allEpisodes.length) {
                    const nextEpisode = this.allEpisodes[currentIndex + 1];
                    this.selectEpisode(nextEpisode.number);
                }
            }
        },


        initEmojiPicker() {
            const picker = new EmojiMart.Picker({
                onEmojiSelect: (emoji) => {
                    this.newComment += emoji.native;
                    this.showEmojiPicker = false;
                }
            });
            document.getElementById('emoji-picker').appendChild(picker);
        },

        saveProgress() {
            // Add validation for server and category
            console.log('lol')
            if (!this.currentServer || !this.currentServer.dataType) return;

            if (this.duration !== null && this.duration !== undefined) return;

            if(this.playerDuration <= 0 || this.currentPlaybackTime <= 0) return;

            console.log(this.playerStatusz)
            const data = {
                anime: this.animeId,
                episode: this.currentEpisodeId,
                currentTime: this.currentPlaybackTime,
                duration: this.playerDuration,
                category: this.currentServer.dataType,
                vide: this.currentServer.serverName,
            };

            // Use navigator.sendBeacon for better reliability
            if (navigator.sendBeacon) {
                const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
                navigator.sendBeacon('/save/progress', blob);
            } else {
                fetch('/save/progress', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                    keepalive: true // Ensure request completes
                });
            }
        },

        searchEpisodes() {
            const searchTerm = this.searchInput.toLowerCase();
            return this.allEpisodes.filter(episode =>
                episode.number.toString().includes(searchTerm) ||
                (episode.title && episode.title.toLowerCase().includes(searchTerm))
            );
        },
        
        get filteredEpisodes() {
            if (!this.searchInput) return this.allEpisodes;
            return this.searchEpisodes();
        },

        postComment() {
            if (this.newComment.trim() !== '') {
                this.isPostingComment = true;
                const newComment = {
                    id: this.comments.length + 1,
                    author: 'User' + Math.floor(Math.random() * 1000),
                    time: 'Just now',
                    content: this.newComment,
                    ep: this.currentEpisode,
                    anime: this.animeId,
                    showReplyForm: false,
                    showReplies: false,
                    replyContent: '',
                    replies: [],
                    isPostingReply: false
                };

                fetch('/anime/comment/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(newComment)
                })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('Server response:', data.data.comment);
                        const newCommentl = {
                            id: data.data.commentId,
                            author: data.data.username,
                            time: 'Just now',
                            content: this.newComment,
                            ep: this.currentEpisode,
                            anime: this.animeId,
                            showReplyForm: false,
                            showReplies: false,
                            replyContent: '',
                            replies: [],
                            isPostingReply: false
                        };
                        this.comments.unshift(newCommentl);
                        this.newComment = '';
                        this.isSpoiler = false;
                        this.total_comments++;

                        anime({
                            targets: this.$el.querySelector('.max-h-[400px] > div:first-child'),
                            translateY: [20, 0],
                            opacity: [0, 1],
                            duration: 600,
                            easing: 'easeOutExpo'
                        });
                    })
                    .catch(error => {
                        console.error('Error posting comment:', error);
                    })
                    .finally(() => {
                        this.isPostingComment = false; // Add this line
                    });
            }
        },

        toggleReply(commentId) {
            const comment = this.comments.find(c => c.id === commentId);
            if (comment) {
                comment.showReplyForm = !comment.showReplyForm;
            }
        },

        toggleReplies(commentId) {
            const comment = this.comments.find(c => c.id === commentId);
            if (comment) {
                comment.showReplies = !comment.showReplies;
            }
        },

        async postReply(commentId) {
            const comment = this.comments.find(c => c.id === commentId);
            if (comment && comment.replyContent.trim() !== '') {
                comment.isPostingReply = true;
                try {
                    const response = await fetch('/anime/comments/reply', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            commentId: commentId,
                            content: comment.replyContent
                        })
                    });

                    if (!response.ok) {
                        throw new Error('Failed to send the reply.');
                    }

                    const reply = await response.json();

                    comment.replies.push({
                        id: reply.id || comment.replies.length + 1,
                        author: reply.author || 'User' + Math.floor(Math.random() * 1000),
                        time: reply.time || 'Just now',
                        content: reply.content || comment.replyContent
                    });

                    comment.replyContent = '';
                    comment.showReplyForm = false;
                    comment.showReplies = true;

                    this.$nextTick(() => {
                        anime({
                            targets: comment.$el.querySelector('.ml-8:last-child'),
                            translateY: [20, 0],
                            opacity: [0, 1],
                            duration: 600,
                            easing: 'easeOutExpo'
                        });
                    });
                } catch (error) {
                    console.error('Error posting reply:', error);
                    alert('Failed to post reply. Please try again later.');
                }finally {
                    comment.isPostingReply = false;
                }
            }
        },

        share(platform) {
            const encodedUrl = encodeURIComponent(this.url);
            const encodedTitle = encodeURIComponent(this.title);
            const encodedDescription = encodeURIComponent(this.description);
            
            const shareUrls = {
                facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}&quote=${encodedTitle}`,
                twitter: `https://twitter.com/intent/tweet?url=${encodedUrl}&text=${encodedTitle}`,
                whatsapp: `https://wa.me/?text=${encodedTitle}%0A${encodedDescription}%0A${encodedUrl}`,
                email: `mailto:?subject=${encodedTitle}&body=${encodedDescription}%0A%0A${encodedUrl}`,
                kakaotalk: `https://story.kakao.com/share?url=${encodedUrl}&title=${encodedTitle}`,
                reddit: `https://reddit.com/submit?url=${encodedUrl}&title=${encodedTitle}&text=${encodedDescription}`,
                telegram: `https://t.me/share/url?url=${encodedUrl}&text=${encodedTitle}%0A${encodedDescription}`
            };

            if (shareUrls[platform]) {
                window.open(shareUrls[platform], '_blank', 'width=600,height=600');
            }
        },

        copyToClipboard() {
            const textToCopy = `${this.title}\n${this.description}\n${this.url}`;
            navigator.clipboard.writeText(textToCopy).then(() => {
                this.copySuccess = true;
                setTimeout(() => {
                    this.copySuccess = false;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        },

        scrollLeft() {
            this.$refs.shareButtons.scrollBy({
                left: -100,
                behavior: 'smooth'
            });
        },

        scrollRight() {
            this.$refs.shareButtons.scrollBy({
                left: 100,
                behavior: 'smooth'
            });
        },
        async vote(commentId, voteType) {
            if (!this.userInfo) {
                window.dispatchEvent(new CustomEvent('trigger-auth-modal'));
                return;
            }else{
                const likesElement = document.querySelector(`[data-comment-id="${commentId}lCount"]`);
                const likeButtonElement = document.querySelector(`[data-comment-id="${commentId}like"]`);
                const dislikeButtonElement = document.querySelector(`[data-comment-id="${commentId}dislike"]`);
                const dislikeButtonLoadingElement = document.querySelector(`[data-button-id="${commentId}disb"]`);
                const likeButtonLodingElement = document.querySelector(`[data-button-id="${commentId}lb"]`);
                
                if (!likesElement) {
                    console.error("Likes element not found for commentId:", commentId);
                    return;
                }

                let likes = parseInt(likesElement.textContent.trim(), 10) || 0;

                try {
                    // Check if voteType should be blocked
                    let don = false;
                    let donl = false;

                    // Block dislike vote if already disliked
                    if (dislikeButtonElement.classList.contains('text-blue-500') && voteType === 'dislike') {
                        don = true;  // Dislike already applied, prevent further vote
                    }
                    // Block like vote if already liked
                    else if (likeButtonElement.classList.contains('text-red-500') && voteType === 'like') {
                        donl = true;  // Like already applied, prevent further vote
                    }

                    // If not already voted
                    if (!don && !donl) {
                        
                        if (voteType === 'like') {
                            likeButtonElement.classList.add('hidden')
                            likeButtonLodingElement.classList.remove('hidden')
                            dislikeButtonElement.disabled = true;
                        }else if(voteType === 'dislike'){
                            dislikeButtonElement.classList.add('hidden')
                            dislikeButtonLoadingElement.classList.remove('hidden')
                            likeButtonElement.disabled = true;
                        }

                        const response = await fetch('/api/anime/comment/respond/' + commentId, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type: voteType }),
                        });

                        if (!response.ok){
                            if (voteType === 'like') {
                                likeButtonElement.classList.remove('hidden')
                                likeButtonLodingElement.classList.add('hidden')
                                dislikeButtonElement.disabled = false;
                            }else if(voteType === 'dislike'){
                                dislikeButtonElement.classList.remove('hidden')
                                dislikeButtonLoadingElement.classList.add('hidden')
                                likeButtonElement.disabled = false;
                            }
                            throw new Error('Failed to vote');
                        };

                        // Handling the "like" vote
                        if (voteType === 'like') {
                            likes++; // Increment likes count

                            // Add "text-red-500" to like button and remove "text-gray-500"
                            likeButtonElement.classList.add('text-red-500');
                            likeButtonElement.classList.remove('text-gray-500');

                            // Add "text-gray-500" to dislike button and remove "text-blue-500"
                            dislikeButtonElement.classList.add('text-gray-500');
                            dislikeButtonElement.classList.remove('text-blue-500');

                            likeButtonElement.classList.remove('hidden')
                            likeButtonLodingElement.classList.add('hidden')
                            dislikeButtonElement.disabled = false;

                            // Animate the like button
                            anime({
                                targets: likeButtonElement,
                                scale: [1, 1.2, 1],
                                duration: 300,
                                easing: 'easeInOutQuad'
                            });
                        }
                        // Handling the "dislike" vote
                        else if (voteType === 'dislike') {
                            likes--; // Decrement likes count

                            // Add "text-blue-500" to dislike button and remove "text-gray-500"
                            dislikeButtonElement.classList.add('text-blue-500');
                            dislikeButtonElement.classList.remove('text-gray-500');

                            // Add "text-gray-500" to like button and remove "text-red-500"
                            likeButtonElement.classList.add('text-gray-500');
                            likeButtonElement.classList.remove('text-red-500');

                            dislikeButtonElement.classList.remove('hidden')
                            dislikeButtonLoadingElement.classList.add('hidden')
                            likeButtonElement.disabled = false;

                            // Animate the dislike button
                            anime({
                                targets: dislikeButtonElement,
                                scale: [1, 1.2, 1],
                                duration: 300,
                                easing: 'easeInOutQuad'
                            });
                        }
                    }

                    // Update DOM with the new likes count
                    likesElement.textContent = likes;

                } catch (error) {
                    console.error('Error voting:', error);
                }
            }
        },
    };
}

// Counter Component
function counter() {
    return {
        count: 0,
        previousCount: 0,
        increasing: false,
        decreasing: false,
        socket: null,
        currentRoom: null,

        init() {
            // Initialize the socket connection
            this.socket = io({ transports: ['websocket'] });

            this.socket.on('connect', () => {
                console.log('Connected to server');
                this.joinRoom();
            });

            // Event handler for initial count
            this.socket.on('current_room_count', (data) => {
                if (data.room === this.currentRoom) {
                    // Alpine will track this property change automatically
                    this.previousCount = this.count;
                    this.count = data.count || 0;
                    
                    this.handleCountChange();
                    console.log('Initial count received:', this.count);
                }
            });

            // Event handler for ongoing updates
            this.socket.on('update_counts', (data) => {
                if (data.room === this.currentRoom) {
                    // Alpine will track this property change automatically
                    this.previousCount = this.count;
                    this.count = data.count || 0;
                    
                    this.handleCountChange();
                    console.log('Count updated via update_counts:', this.count);
                }
            });

            // Listen for URL changes if it's a SPA
            window.addEventListener('popstate', () => this.joinRoom());
        },

        handleCountChange() {
            if (this.count > this.previousCount) {
                this.animateCountChange('up');
            } else if (this.count < this.previousCount) {
                this.animateCountChange('down');
            }
        },

        joinRoom() {
            const currentUrl = window.location.href;
            const url = new URL(currentUrl);
            const pathname = url.pathname;
            const part = pathname.substring(pathname.indexOf('/watch'), pathname.lastIndexOf('/') + 1);

            if (this.currentRoom) {
                this.socket.emit('leave', { room: this.currentRoom });
            }
            
            this.currentRoom = part;
            this.socket.emit('join', { other_id: this.currentRoom });
            this.socket.emit('get_current_room_count', { room: this.currentRoom });
        },

        formatCount(num) {
            return num > 999 ? (num / 1000).toFixed(1) + 'k' : num;
        },

        animateCountChange(direction) {
            if (direction === 'up') {
                this.increasing = true;
                this.decreasing = false;
            } else {
                this.increasing = false;
                this.decreasing = true;
            }

            setTimeout(() => {
                this.increasing = false;
                this.decreasing = false;
            }, 300);
        }
    };
}
// Like System Component
function likeSystem(config) {
    return {
        userInfo: typeof config.userInfo === 'string' ? JSON.parse(config.userInfo) : config.userInfo,
        likes: config.likes || 0,
        dislikes: config.dislikes || 0,
        liked: config.userLiked || false,
        disliked: config.userUnliked || false,
        anime: config.animeId,
        isLoading: false,

        createParticles(buttonId, particleClass) {
            const button = document.getElementById(buttonId);
            if (!button) return;
            
            const rect = button.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;
            
            // Add button pop animation
            button.classList.remove('button-pop');
            void button.offsetWidth; // Force reflow
            button.classList.add('button-pop');
            
            // Create 8 particles
            for (let i = 0; i < 8; i++) {
                const particle = document.createElement('div');
                particle.classList.add('particle', particleClass);
                
                // Random size between 3-6px
                const size = Math.random() * 3 + 3;
                particle.style.width = `${size}px`;
                particle.style.height = `${size}px`;
                
                // Random direction
                const angle = Math.random() * Math.PI * 2;
                const distance = 20 + Math.random() * 20;
                const tx = Math.cos(angle) * distance;
                const ty = Math.sin(angle) * distance;
                
                particle.style.setProperty('--tx', `${tx}px`);
                particle.style.setProperty('--ty', `${ty}px`);
                
                // Position at center of button
                particle.style.left = `${centerX}px`;
                particle.style.top = `${centerY}px`;
                
                document.body.appendChild(particle);
                
                // Remove particle after animation completes
                setTimeout(() => {
                    particle.remove();
                }, 600);
            }
        },

        async like() {
            if (!this.userInfo) {
                window.dispatchEvent(new CustomEvent('trigger-auth-modal'));
                return;
            }

            if (!this.liked && !this.isLoading) {
                this.isLoading = true;
                try {
                    const response = await fetch(`/api/anime/respond/${this.anime}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            type: 'like',
                        }),
                    });

                    if (response.ok) {
                        this.likes++;
                        this.liked = true;

                        if (this.disliked) {
                            this.dislikes--;
                            this.disliked = false;
                        }

                        this.animateButton('like-button');
                    }
                } catch (error) {
                    console.error('Error during like operation:', error);
                } finally {
                    this.isLoading = false;
                }
            }
        },

        async dislike() {
            if (!this.userInfo) {
                window.dispatchEvent(new CustomEvent('trigger-auth-modal'));
                return;
            }

            if (!this.disliked && !this.isLoading) {
                this.isLoading = true;
                try {
                    const response = await fetch(`/api/anime/respond/${this.anime}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            type: 'dislike',
                        }),
                    });

                    if (response.ok) {
                        this.dislikes++;
                        this.disliked = true;

                        if (this.liked) {
                            this.likes--;
                            this.liked = false;
                        }

                        this.animateButton('dislike-button');
                    }
                } catch (error) {
                    console.error('Error during dislike operation:', error);
                } finally {
                    this.isLoading = false;
                }
            }
        },

        animateButton(buttonClass) {
            const button = document.querySelector(`.${buttonClass}`);
            anime({
                targets: button,
                scale: [1, 1.2, 1],
                duration: 300,
                easing: 'easeInOutQuad'
            });
        }
    };
}

function watchlist(config) {
    return {
        // Configuration and state properties
        open: false,
        selectedFolder: '',
        folders: ['Plan To Watch', 'Watching', 'Completed', 'On Hold', 'Dropped', 'Remove'],
        animeId: config.animeId,
        loading: null,
        success: null,
        error: null,
        inWatchlist: config.animeIInfo.inWatchlist,
        currentFolder: config.animeIInfo.folder,
        dropdownOpen: false,
        isLoading: false,
        
        // Toggle dropdown visibility
        toggleDropdown() {
            this.dropdownOpen = !this.dropdownOpen;
        },
        
        // Add anime to selected watchlist folder
        addToWatchlist(folder) {
            this.selectedFolder = folder;
            this.loading = folder;
            this.success = null;
            this.error = null;
            this.isLoading = true;

            fetch(`/add-to-watchlist/${folder}/${this.animeId}`, {
                method: 'GET',
            })
            .then(response => response.json())
            .then(data => {
                this.loading = null;
                this.isLoading = false;
                if (data.success) {
                    this.success = folder;
                    if (folder == 'Remove'){
                        this.inWatchlist = false;
                    } else {
                        const statusMap = {
                            "Watching": "CURRENT",
                            "Plan To Watch": "PLANNING",
                            "Completed": "COMPLETED",
                            "Dropped": "DROPPED",
                            "On Hold": "PAUSED"
                        };
                        const status = statusMap[folder] || "PLANNING";
                        fetch("https://graphql.anilist.co", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                                "Accept": "application/json",
                                "Authorization": `Bearer ${data.data.token}`
                            },
                            body: JSON.stringify({
                                query: `
                                mutation ($mediaId: Int!, $status: MediaListStatus) {
                                    SaveMediaListEntry(mediaId: $mediaId, status: $status) {
                                        id
                                        status
                                    }
                                }
                                `,
                                variables: { mediaId: data.data.anilist, status }
                            })
                        })
                        .then(res => res.json())
                        .then(response => {
                            if (response.errors) {
                                throw new Error(response.errors.map(err => err.message).join(", "));
                            }
                            console.log(response);
                        })
                        .catch(err => {
                            console.error("AniList error:", err);
                            window.dispatchEvent(new CustomEvent('notify', {
                                detail: { message: `AniList error: ${err.message}`, type: 'error' }
                            }));
                        });
                        this.inWatchlist = true;
                    }
                    this.currentFolder = folder;
                    this.animateIcon('success');
                    this.dropdownOpen = false;  // Close dropdown after successful addition
                } else {
                    this.error = folder;
                    this.animateIcon('error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                this.loading = null;
                this.isLoading = false;
                this.error = folder;
                this.animateIcon('error');
            });
        },
        
        // Create particle animation effects
        createParticles(buttonId, particleClass) {
            const button = document.getElementById(buttonId);
            if (!button) return;
            
            const rect = button.getBoundingClientRect();
            const centerX = rect.left + rect.width / 2;
            const centerY = rect.top + rect.height / 2;
            
            for (let i = 0; i < 10; i++) {
                const particle = document.createElement('div');
                particle.className = `particle ${particleClass}`;
                
                // Random position
                const angle = Math.random() * Math.PI * 2;
                const distance = 30 + Math.random() * 30;
                const tx = Math.cos(angle) * distance;
                const ty = Math.sin(angle) * distance;
                
                // Set CSS variables for the animation
                particle.style.setProperty('--tx', `${tx}px`);
                particle.style.setProperty('--ty', `${ty}px`);
                
                // Set size and starting position
                particle.style.width = `${3 + Math.random() * 4}px`;
                particle.style.height = particle.style.width;
                particle.style.left = `${centerX}px`;
                particle.style.top = `${centerY}px`;
                
                document.body.appendChild(particle);
                
                // Remove particle after animation completes
                particle.addEventListener('animationend', () => {
                    particle.remove();
                });
            }
            
            // Animate button
            button.classList.remove('button-pop');
            void button.offsetWidth; // Force reflow
            button.classList.add('button-pop');
        },
        
        // Animate icon for success or error states
        animateIcon(type) {
            const element = document.querySelector(`[x-show="${type} === '${this.selectedFolder}']`);
            if (element) {
                anime({
                    targets: element,
                    scale: [0, 1],
                    opacity: [0, 1],
                    duration: 300,
                    easing: 'easeOutQuad'
                });
            }
        }
    };
}

// INITIALIZATION ==============================================================
document.addEventListener('alpine:init', () => {
    // Get config from inline script
    const watchConfig = window.__watchConfig__;
    
    // Register components with Alpine.js
    Alpine.data('animePlayer', () => animePlayer(watchConfig));
    Alpine.data('counter', counter);
    Alpine.data('likeSystem', () => likeSystem(watchConfig));
    Alpine.data('watchlist', () => watchlist(watchConfig));
    
});