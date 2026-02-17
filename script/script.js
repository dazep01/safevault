// SAFEVAULT CORE - CANONICAL IMPLEMENTATION v2.4
// ===========================================
// FIXED: Loading Screen & Transition Issues
// ===========================================
// DEV only — comment out or gate behind a debug flag for production
if (location.hostname === 'localhost') {
	if ('serviceWorker' in navigator) {
		navigator.serviceWorker.getRegistrations()
			.then(regs => regs.forEach(r => r.unregister()));
	}
}
// ===========================================
// PRELOAD OPTIMIZATION
// ===========================================
const preconnectLinks = [
	'https://unpkg.com',
	'https://cdnjs.cloudflare.com/ajax/libs'
];

preconnectLinks.forEach(origin => {
	if (!document.querySelector(`link[href="${origin}"]`)) {
		const link = document.createElement('link');
		link.rel = 'preconnect';
		link.href = origin;
		link.crossOrigin = 'anonymous';
		document.head.appendChild(link);
	}
});

// ===========================================
// GLOBAL STATE & CONSTANTS
// ===========================================
const SafeVault = {
	// === STATE OBJECTS ===
	currentVault: null,
	currentVaultId: null,
	currentVaultItems: [],
	currentScreen: null,

	// === CRYPTO STATE ===  
	cryptoBoundary: {
		encCryptoKey: null,
		authCryptoKey: null,
		kdfParams: null
	},

	// === CRYPTO CONSTANTS ===  
	MAGIC_BYTES: new TextEncoder().encode('SAFEVAULT_MAGIC_v2.4_2026'),
	CRYPTO: {
		ALGO: 'AES-GCM',
		IV_LENGTH: 12,
		TAG_LENGTH: 128,
		KDF_TYPE: argon2.ArgonType.Argon2id,
		KDF_HASH_LEN: 64,
		KDF_SALT_LENGTH: 16,
		KEY_LENGTH: 32,
		MIN_KDF_TIME: 3,
		MIN_KDF_MEMORY: 102400
	},

	// === APP CONFIG ===  
	config: {
		autoLockMinutes: 5,
		clipboardTimeout: 30,
		maxFailedAttempts: 5,
		backoffBaseMs: 1000,
		backoffMaxMs: 3600000,
		minUnlockDelayMs: 500,
		jitterRangeMs: 100,
		batchSize: 5,
		cacheSize: 100,
		useWebWorkers: true,
		enableEmergencyAccess: true,
		enablePasswordHints: true,
		enableBulkOperations: true,
		enableDuplicateDetection: true,
		theme: 'auto',
		animations: true,
		confirmDeletes: true,
		confirmExports: true,
		argon2Params: {
			time: 3,
			mem: 65536,
			parallelism: 2
		},
		exportFormats: ['json', 'encrypted', 'csv'],
		backupRetention: 30,
		logLevel: 'warn',
		enableTelemetry: false,
		checkForUpdates: true,
		updateChannel: 'stable',
		enableAuditLog: true,
		auditLogRetention: 90
	},

	// === DOM ELEMENTS CACHE ===  
	elements: {},

	// === TIMERS & SYNC ===  
	timers: {
		autoLock: null,
		clipboard: null,
		idle: null,
		autoLockWarning: null,
		countdown: null
	},
	broadcastChannel: null,
	db: null,
	timerInterval: null,
	lockUntil: null,


	// ===========================================
	// FIXED INITIALIZATION & TRANSITION
	// ===========================================
	init: async function() {
		console.log('SafeVault: Starting fixed initialization...');

		try {
			// Phase 1: Pastikan DOM siap
			if (document.readyState !== 'complete') {
				await new Promise(resolve => {
					if (document.readyState === 'loading') {
						document.addEventListener('DOMContentLoaded', resolve);
					} else {
						resolve();
					}
				});
			}

			// Phase 2: Cache elements
			this.cacheElements();

			// Phase 3: Critical checks
			this.updateLoadStatus('Checking environment...', 20);
			await this.checkCriticalAPIs();

			// Phase 4: Storage
			this.updateLoadStatus('Initializing storage...', 40);
			await this.initStorage();

			// Phase 5: Vault discovery
			this.updateLoadStatus('Checking vaults...', 60);
			const vaults = await this.getAllVaults();
			const hasVaults = vaults && vaults.length > 0;

			// Phase 6: Setup
			this.updateLoadStatus('Setting up security...', 80);
			this.setupEventListeners();
			this.initMultiTabSync();
			this.initSort();

			// Phase 7: Complete
			this.updateLoadStatus('Ready!', 100);

			// Tunggu animasi loading selesai
			await new Promise(r => setTimeout(r, 500));

			// Phase 8: SINKRON transition - tidak ada async
			this.hideLoadingAndShowApp(hasVaults);

		} catch (error) {
			console.error('Initialization failed:', error);
			this.handleCriticalError(error);
		}
	},

	// ===========================================
	// FIXED: SYNCHRONOUS TRANSITION FUNCTION
	// ===========================================
	hideLoadingAndShowApp: function(hasVaults) {
		const TRANSITION_MS = 420; // harus sinkron dengan CSS
		console.log('[TRANSITION] hideLoadingAndShowApp, hasVaults:', hasVaults);

		// 1) Cari loading element (cached first)
		const loadingScreen = this.elements?.loadingScreen ||
			document.getElementById('initialLoadScreen') ||
			document.getElementById('loadingScreen');

		if (!loadingScreen) {
			console.error('Loading screen not found!');
			// hard-hide legacy ids just in case, then fallback
			['initialLoadScreen', 'loadingScreen'].forEach(id => {
				const el = document.getElementById(id);
				if (el) {
					el.style.display = 'none';
					el.classList.remove('active', 'exiting');
				}
			});
			return this.emergencyShowLockScreen();
		}

		// 2) Tentukan target screen
		let targetScreenId;
		const registry = JSON.parse(localStorage.getItem('safevault_registry') || '{}');
		if (hasVaults) targetScreenId = registry.onboarding_completed ? 'lockScreen' : 'onboardingScreen';
		else targetScreenId = 'onboardingScreen';
		console.log('[TRANSITION] Target screen:', targetScreenId);

		// 3) Play exit animation on loading + initial (if present)
		loadingScreen.classList.add('exiting');
		const initEl = document.getElementById('initialLoadScreen');
		if (initEl && initEl !== loadingScreen) initEl.classList.add('exiting');

		// 4) Setelah transisi selesai -> bersihkan DOM lalu tunjukkan target
		setTimeout(() => {
			try {
				console.warn('REMOVING initialLoadScreen FROM DOM (if present)');
				// hide & remove loadingScreen safely
				loadingScreen.classList.remove('active', 'exiting');
				loadingScreen.style.display = 'none';
				if (loadingScreen.parentNode && loadingScreen.id === 'initialLoadScreen') {
					loadingScreen.parentNode.removeChild(loadingScreen);
				} else if (loadingScreen.parentNode && loadingScreen.id === 'loadingScreen') {
					// keep but hidden OR remove to avoid overlay problems
					loadingScreen.parentNode.removeChild(loadingScreen);
				}

				// remove initialLoadScreen if it's a separate node
				if (initEl && initEl.parentNode) {
					initEl.classList.remove('active', 'exiting');
					initEl.style.display = 'none';
					initEl.parentNode.removeChild(initEl);
				}
			} catch (e) {
				console.warn('Failed to fully remove loading elements:', e);
			}

			// allow scrolling again
			document.body.style.overflow = '';

			// 5) Show target screen (synchronous)
			const targetScreen = document.getElementById(targetScreenId);
			if (targetScreen) {
				targetScreen.style.display = 'flex';
				targetScreen.classList.add('active');
				this.currentScreen = targetScreenId;

				// auto-focus for lock screen
				if (targetScreenId === 'lockScreen') {
					setTimeout(() => {
						const input = document.getElementById('masterPassInput');
						if (input) input.focus();
					}, 100);
				}

				console.log('[TRANSITION] Successfully showed:', targetScreenId);
				// 🔥 HARD CLEANUP: buang style injector loading
				[...document.styleSheets]
				.filter(s => !s.href)
					.forEach(s => s.ownerNode.remove());

				document.body.style.overflow = '';
			} else {
				console.error('Target screen not found:', targetScreenId);
				this.emergencyShowLockScreen();
			}
		}, TRANSITION_MS);
	},

	handleCriticalError: function(error) {
		console.error('Critical error:', error);

		// Update loading screen dengan error message
		const loader = this.elements.loadingScreen || document.getElementById('initialLoadScreen') || document.getElementById('loadingScreen');
		if (loader) {
			loader.innerHTML = `
            <div class="card" style="max-width: 400px; text-align: center;">
                <div class="mb-xl">
                    <i class="ph ph-warning-circle" style="font-size: 64px; color: var(--danger);"></i>
                </div>
                <h2 class="mb-sm">Initialization Failed</h2>
                <p class="caption mb-lg">${this.escapeHTML(error.message)}</p>
                <div class="grid grid-2 gap-md">
                    <button class="ios-button secondary" onclick="location.reload()">
                        <i class="ph ph-arrows-clockwise"></i> Retry
                    </button>
                    <button class="ios-button" onclick="SafeVault.emergencyShowLockScreen()">
                        <i class="ph ph-first-aid"></i> Continue Anyway
                    </button>
                </div>
            </div>
        `;
		}
	},

	waitForDOMReady: function() {
		return new Promise(resolve => {
			if (document.readyState === 'loading') {
				document.addEventListener('DOMContentLoaded', resolve);
			} else {
				resolve();
			}
		});
	},

	checkCriticalAPIs: async function() {
		const checks = [{
				name: 'Web Crypto API',
				check: () => typeof crypto !== 'undefined' && crypto.subtle
			},
			{
				name: 'IndexedDB',
				check: () => typeof indexedDB !== 'undefined'
			},
			{
				name: 'LocalStorage',
				check: () => typeof localStorage !== 'undefined'
			},
			{
				name: 'Uint8Array',
				check: () => typeof Uint8Array !== 'undefined'
			}
		];

		for (const check of checks) {
			if (!check.check()) {
				throw new Error(`${check.name} not available`);
			}
		}

		// Check for Argon2
		if (typeof argon2 === 'undefined') {
			console.warn('Argon2 not loaded, will use PBKDF2 fallback');
		}
	},

	// ===========================================
	// FIXED SCREEN TRANSITION SYSTEM
	// ===========================================
	performSafeTransition: async function(hasVaults) {
		console.log('[TRANSITION] Starting transition, hasVaults:', hasVaults);

		// 1. Hide loading screen with animation
		const loader = this.elements.loadingScreen || document.getElementById('initialLoadScreen') || document.getElementById('loadingScreen');
		if (loader) {
			loader.style.opacity = '0';
			loader.style.transition = 'opacity 0.4s ease';

			await new Promise(r => setTimeout(r, 400));
			loader.style.display = 'none';
		}

		// 2. Determine target screen
		let targetScreenId;
		if (hasVaults) {
			const registry = JSON.parse(localStorage.getItem('safevault_registry') || '{}');
			if (registry.onboarding_completed) {
				targetScreenId = 'lockScreen';
			} else {
				targetScreenId = 'onboardingScreen';
			}
		} else {
			targetScreenId = 'onboardingScreen';
		}

		console.log('[TRANSITION] Target screen:', targetScreenId);

		// 3. Show target screen
		this.showScreen(targetScreenId);

		// 4. Auto-focus for lock screen
		if (targetScreenId === 'lockScreen') {
			setTimeout(() => {
				const input = document.getElementById('masterPassInput');
				if (input) input.focus();
			}, 100);
		}
	},

	// ===========================================
	// FIXED: SHOW SCREEN FUNCTION (SIMPLIFIED)
	// ===========================================
	showScreen: function(screenId) {
		console.log('[SCREEN] showScreen called:', screenId);

		// Validasi
		if (!screenId || this.currentScreen === screenId) return;

		const target = document.getElementById(screenId);
		if (!target) {
			console.error('Screen not found:', screenId);
			return;
		}

		// Hide current screen jika ada
		if (this.currentScreen) {
			const current = document.getElementById(this.currentScreen);
			if (current) {
				current.classList.remove('active');
				setTimeout(() => {
					current.style.display = 'none';
				}, 300);
			}
		}

		// Show target screen
		this.currentScreen = screenId;
		target.style.display = 'flex';

		// Trigger reflow
		void target.offsetWidth;

		// Add active class untuk animasi
		target.classList.add('active');

		// Auto-focus untuk lock screen
		if (screenId === 'lockScreen') {
			setTimeout(() => {
				const input = target.querySelector('input[type="password"]');
				if (input) input.focus();
			}, 100);
		}

		console.log('[SCREEN] Now showing:', screenId);
	},

	// ===========================================
	// EMERGENCY FALLBACK
	// ===========================================
	emergencyShowLockScreen: function() {
		['initialLoadScreen', 'loadingScreen'].forEach(id => {
			const el = document.getElementById(id);
			if (el) {
				el.style.display = 'none';
				el.classList.remove('active', 'exiting');
			}
		});
		console.error('[EMERGENCY] Showing lock screen as fallback');

		// Sembunyikan semua screen
		document.querySelectorAll('.screen').forEach(screen => {
			screen.style.display = 'none';
			screen.classList.remove('active');
		});

		// Tampilkan lock screen
		const lockScreen = document.getElementById('lockScreen');
		if (lockScreen) {
			lockScreen.style.display = 'flex';
			lockScreen.classList.add('active');
			this.currentScreen = 'lockScreen';

			// Reset input
			const input = lockScreen.querySelector('input[type="password"]');
			if (input) input.value = '';

			console.log('[EMERGENCY] Lock screen shown');
			return true;
		}

		// Last resort: reload
		console.error('[EMERGENCY] No screens available, reloading...');
		setTimeout(() => location.reload(), 1000);
		return false;
	},

	emergencyFallback: function() {
		console.error('[EMERGENCY] Activating fallback system');

		// Try to show any available screen
		const screens = ['lockScreen', 'onboardingScreen', 'createVaultScreen'];

		for (const screenId of screens) {
			const screen = document.getElementById(screenId);
			if (screen) {
				this.showScreen(screenId);
				console.log('[EMERGENCY] Fallback to:', screenId);
				return true;
			}
		}

		console.error('[EMERGENCY] No screens available');
		return false;
	},

	handleInitError: function(error) {
		const loader = this.elements.loadingScreen || document.getElementById('initialLoadScreen') || document.getElementById('loadingScreen');
		if (!loader) return;

		const card = loader.querySelector('.card');
		if (card) {
			card.innerHTML = `
                <div class="text-center">
                    <div class="mb-xl">
                        <i class="ph ph-warning-circle" style="font-size: 64px; color: var(--danger);"></i>
                    </div>
                    <h2 class="mb-sm">Initialization Failed</h2>
                    <p class="caption mb-lg">${this.escapeHTML(error.message)}</p>
                    <div class="grid grid-2 gap-md">
                        <button class="ios-button secondary" onclick="location.reload()">
                            <i class="ph ph-arrows-clockwise"></i> Retry
                        </button>
                        <button class="ios-button" onclick="SafeVault.emergencyFallback()">
                            <i class="ph ph-first-aid"></i> Continue
                        </button>
                    </div>
                </div>
            `;
		}
	},

	// ===========================================
	// UPDATE LOAD STATUS
	// ===========================================
	updateLoadStatus: function(message, progress) {
		const statusEl = document.getElementById('loadStatus');
		const progressEl = document.getElementById('loadProgress');

		if (statusEl) statusEl.textContent = message;
		if (progressEl) progressEl.style.width = `${progress}%`;

		console.log(`[LOAD] ${progress}%: ${message}`);
	},

	// ===========================================
	// DOM ELEMENT CACHING
	// ===========================================
	cacheElements: function() {
		this.elements = {
			// Inputs
			masterPassInput: document.getElementById('masterPassInput'),
			newMasterPassword: document.getElementById('newMasterPassword'),
			confirmMasterPassword: document.getElementById('confirmMasterPassword'),
			vaultName: document.getElementById('vaultName'),
			passwordHint: document.getElementById('passwordHint'),
			itemLabel: document.getElementById('itemLabel'),
			itemValue: document.getElementById('itemValue'),

			// Screens
			lockScreen: document.getElementById('lockScreen'),
			onboardingScreen: document.getElementById('onboardingScreen'),
			createVaultScreen: document.getElementById('createVaultScreen'),
			loadingScreen: document.getElementById('loadingScreen') || document.getElementById('initialLoadScreen'),
			mainApp: document.getElementById('mainApp'),

			// Others
			timerDisplay: document.getElementById('timerDisplay')
		};

		// Validate critical elements
		const critical = ['lockScreen', 'onboardingScreen', 'createVaultScreen', 'loadingScreen', 'mainApp'];
		critical.forEach(id => {
			if (!document.getElementById(id)) {
				console.warn(`Critical element missing: ${id}`);
			}
		});
	},

	// ===========================================
	// STORAGE INITIALIZATION
	// ===========================================
	initStorage: async function() {
		// Initialize registry
		let registry = localStorage.getItem('safevault_registry');
		if (!registry) {
			registry = {
				vault_ids: [],
				active_vault_id: null,
				onboarding_completed: false,
				schema_version: 3
			};
			localStorage.setItem('safevault_registry', JSON.stringify(registry));
		}

		// Initialize IndexedDB
		return new Promise((resolve, reject) => {
			const request = indexedDB.open('SafeVaultDB', 4);

			request.onerror = () => reject(request.error);

			request.onupgradeneeded = (event) => {
				const db = event.target.result;
				const oldVersion = event.oldVersion || 0;

				if (oldVersion < 4) {
					if (!db.objectStoreNames.contains('vault_items')) {
						const store = db.createObjectStore('vault_items', {
							keyPath: 'item_id',
							autoIncrement: true
						});
						store.createIndex('vault_id', 'vault_id', {
							unique: false
						});
					}

					if (!db.objectStoreNames.contains('vaults')) {
						db.createObjectStore('vaults', {
							keyPath: 'vault_id'
						});
					}

					if (!db.objectStoreNames.contains('audit_logs')) {
						const auditStore = db.createObjectStore('audit_logs', {
							keyPath: 'id',
							autoIncrement: true
						});
						auditStore.createIndex('timestamp', 'timestamp', {
							unique: false
						});
						auditStore.createIndex('vaultId', 'vaultId', {
							unique: false
						});
					}
				}
			};

			request.onsuccess = () => {
				this.db = request.result;
				resolve(this.db);
			};
		});
	},

	// ======================================
	// SECURITY UTILITIES
	// ======================================
	constantTimeEqualBytes: function(a, b) {
		if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
			throw new Error('Inputs must be Uint8Array');
		}
		if (a.length !== b.length) return false;

		let result = 0;
		for (let i = 0; i < a.length; i++) {
			result |= a[i] ^ b[i];
		}
		return result === 0;
	},

	zeroizeUint8: function(arr) {
		if (arr instanceof Uint8Array) {
			try {
				arr.fill(0);
			} catch (e) {
				console.warn('Zeroization warning:', e.message);
			}
		}
	},

	zeroizeString: function(str) {
		return '';
	},

	// ===========================================
	// SHA-256 HELPER (FOR RECOVERY KEY HASHING)
	// ===========================================
	sha256Hex: async function(input) {
		const encoder = new TextEncoder();
		const data = encoder.encode(input);
		const hash = await crypto.subtle.digest('SHA-256', data);
		const hashArray = Array.from(new Uint8Array(hash));
		return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
	},

	applyAntiTimingDelay: async function() {
		const minDelay = this.config.minUnlockDelayMs;
		const jitter = Math.random() * this.config.jitterRangeMs;
		await new Promise(resolve => setTimeout(resolve, minDelay + jitter));
	},

	// ===========================================
	// DATA CONVERSION
	// ===========================================
	hexToUint8Array: function(hex) {
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
		}
		return bytes;
	},

	uint8ArrayToHex: function(bytes) {
		return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
	},

	base64ToUint8Array: function(base64) {
		const binary = atob(base64);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes;
	},

	arrayBufferToBase64: function(bufferOrView) {
		const view = bufferOrView instanceof Uint8Array ? bufferOrView : new Uint8Array(bufferOrView);
		let binary = '';
		for (let i = 0; i < view.byteLength; i++) binary += String.fromCharCode(view[i]);
		return btoa(binary);
	},

	// ===========================================
	// KEY DERIVATION
	// ===========================================
	deriveKeys: async function(password, salt, params = null) {
		const kdfParams = params || {
			time: 3,
			mem: 65536,
			parallelism: 2,
			hashLen: this.CRYPTO.KDF_HASH_LEN,
			type: this.CRYPTO.KDF_TYPE
		};

		try {
			const result = await argon2.hash({
				pass: password,
				salt: salt,
				time: kdfParams.time,
				mem: kdfParams.mem,
				parallelism: kdfParams.parallelism,
				hashLen: kdfParams.hashLen,
				type: kdfParams.type,
				raw: true
			});

			let hashBytes;

			if (result.hash instanceof Uint8Array) {
				hashBytes = result.hash;
			} else if (result.hash instanceof ArrayBuffer) {
				hashBytes = new Uint8Array(result.hash);
			} else if (typeof result.hash === 'string' && /^[0-9a-f]+$/i.test(result.hash)) {
				hashBytes = this.hexToUint8Array(result.hash);
			} else if (typeof result.hash === 'string') {
				hashBytes = this.base64ToUint8Array(result.hash);
			} else {
				throw new Error('Unsupported argon2 hash format');
			}

			if (hashBytes.length !== this.CRYPTO.KDF_HASH_LEN) {
				throw new Error(`Argon2 hash length mismatch: expected ${this.CRYPTO.KDF_HASH_LEN}, got ${hashBytes.length}`);
			}

			const rawEncKey = hashBytes.slice(0, 32);
			const rawAuthKey = hashBytes.slice(32, 64);

			return {
				rawEncKey: rawEncKey,
				rawAuthKey: rawAuthKey,
				kdfParams: kdfParams
			};

		} catch (error) {
			console.warn('Argon2 KDF failed, falling back to PBKDF2:', error);
			return this.deriveKeysFallback(password, salt);
		}
	},

	deriveKeysFallback: async function(password, salt) {
		const encoder = new TextEncoder();
		const passwordBytes = encoder.encode(password);

		const keyMaterial = await crypto.subtle.importKey(
			'raw',
			passwordBytes, {
				name: 'PBKDF2'
			},
			false,
			['deriveBits']
		);

		const derivedBits = await crypto.subtle.deriveBits({
				name: 'PBKDF2',
				salt: salt,
				iterations: 210000,
				hash: 'SHA-256'
			},
			keyMaterial,
			512
		);

		const hashBytes = new Uint8Array(derivedBits);

		return {
			rawEncKey: hashBytes.slice(0, 32),
			rawAuthKey: hashBytes.slice(32, 64),
			kdfParams: {
				type: 'pbkdf2',
				iterations: 210000
			}
		};
	},

	// ===========================================
	// CRYPTO OPERATIONS
	// ===========================================
	importAesKeyFromRaw: async function(rawKeyBytes, usages = ['encrypt', 'decrypt']) {
		if (!(rawKeyBytes instanceof Uint8Array)) {
			throw new Error('rawKeyBytes must be Uint8Array');
		}

		if (rawKeyBytes.length !== 32) {
			throw new Error(`rawKeyBytes must be 32 bytes, got ${rawKeyBytes.length}`);
		}

		const keyBuffer = rawKeyBytes.buffer.slice(
			rawKeyBytes.byteOffset,
			rawKeyBytes.byteOffset + rawKeyBytes.byteLength
		);

		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			keyBuffer, {
				name: this.CRYPTO.ALGO
			},
			false,
			usages
		);

		return cryptoKey;
	},

	importHmacKeyFromRaw: async function(rawAuthKey) {
		if (!(rawAuthKey instanceof Uint8Array)) {
			throw new Error('rawAuthKey must be Uint8Array');
		}

		if (rawAuthKey.length !== 32) {
			throw new Error(`rawAuthKey must be 32 bytes, got ${rawAuthKey.length}`);
		}

		const keyBuffer = rawAuthKey.buffer.slice(
			rawAuthKey.byteOffset,
			rawAuthKey.byteOffset + rawAuthKey.byteLength
		);

		return await crypto.subtle.importKey(
			'raw',
			keyBuffer, {
				name: 'HMAC',
				hash: {
					name: 'SHA-256'
				}
			},
			false,
			['sign', 'verify']
		);
	},

	encryptData: async function(plaintextOrBytes, encCryptoKey) {
		if (!(encCryptoKey instanceof CryptoKey)) throw new Error('encCryptoKey must be CryptoKey');
		if (!encCryptoKey.usages.includes('encrypt')) throw new Error('CryptoKey lacks encrypt permission');

		let plaintextBytes;
		if (plaintextOrBytes instanceof Uint8Array) plaintextBytes = plaintextOrBytes;
		else if (plaintextOrBytes instanceof ArrayBuffer) plaintextBytes = new Uint8Array(plaintextOrBytes);
		else plaintextBytes = new TextEncoder().encode(String(plaintextOrBytes));

		const iv = crypto.getRandomValues(new Uint8Array(this.CRYPTO.IV_LENGTH));
		const ciphertext = await crypto.subtle.encrypt({
				name: this.CRYPTO.ALGO,
				iv: iv,
				tagLength: this.CRYPTO.TAG_LENGTH
			},
			encCryptoKey,
			plaintextBytes
		);
		return {
			iv,
			ciphertext
		};
	},

	decryptData: async function(iv, ciphertext, encCryptoKey) {
		if (!(encCryptoKey instanceof CryptoKey)) throw new Error('encCryptoKey must be CryptoKey');
		if (!encCryptoKey.usages.includes('decrypt')) throw new Error('CryptoKey lacks decrypt permission');

		try {
			const plainBuffer = await crypto.subtle.decrypt({
					name: this.CRYPTO.ALGO,
					iv: iv,
					tagLength: this.CRYPTO.TAG_LENGTH
				},
				encCryptoKey,
				ciphertext
			);
			return new Uint8Array(plainBuffer);
		} catch (err) {
			throw new Error('DECRYPTION_FAILED_AUTH');
		}
	},

	// ===========================================
	// VAULT UNLOCK FLOW
	// ===========================================
	yieldToUI: function() {
		return new Promise(resolve => requestAnimationFrame(resolve));
	},

	showOverlaySpinner: function(text) {
		const el = document.getElementById('overlaySpinner');
		if (!el) return;

		if (text) {
			el.querySelector('.spinner-text').textContent = text;
		}

		el.classList.remove('hidden');
	},

	hideOverlaySpinner: function() {
		document.getElementById('overlaySpinner')?.classList.add('hidden');
	},

	attemptUnlock: async function() {
		const password = this.elements.masterPassInput?.value;

		// 1. Validasi Awal
		if (!password || password.length < 1) {
			this.showToast('Masukkan password', 'info');
			return;
		}

		if (!this.canAttemptUnlock()) {
			return;
		}

		await this.applyAntiTimingDelay();

		if (typeof argon2 === 'undefined') {
			throw new Error('Argon2 library not loaded');
		}

		// 2. Tampilkan Spinner
		this.showOverlaySpinner('Verifikasi vault identity...');
		await this.yieldToUI();

		try {
			const vaults = await this.getAllVaults();

			let unlockedVault = null;
			let foundEncCryptoKey = null;
			let foundAuthCryptoKey = null;
			let foundKdfParams = null;

			// Mulai Iterasi Vault
			for (const vault of vaults) {
				let derivedKeys = null;
				let importedEncKey = null;
				let importedAuthKey = null;

				try {
					const salt = this.hexToUint8Array(vault.salt);

					derivedKeys = await this.deriveKeys(password, salt, vault.kdf_params);

					importedEncKey = await this.importAesKeyFromRaw(
						derivedKeys.rawEncKey,
						['decrypt']
					);

					importedAuthKey = await this.importHmacKeyFromRaw(
						derivedKeys.rawAuthKey
					);

					const encryptedMagic = this.base64ToUint8Array(vault.key_check_encrypted);
					const iv = encryptedMagic.slice(0, this.CRYPTO.IV_LENGTH);
					const ciphertext = encryptedMagic.slice(this.CRYPTO.IV_LENGTH).buffer;

					const decryptedMagicBytes = await this.decryptData(iv, ciphertext, importedEncKey);

					const fullEncCryptoKey = await this.importAesKeyFromRaw(
						derivedKeys.rawEncKey,
						['encrypt', 'decrypt']
					);

					// Cek apakah hasil dekripsi cocok dengan Magic Bytes
					if (this.constantTimeEqualBytes(this.MAGIC_BYTES, decryptedMagicBytes)) {
						unlockedVault = vault;
						foundEncCryptoKey = fullEncCryptoKey;
						foundAuthCryptoKey = importedAuthKey;
						foundKdfParams = derivedKeys.kdfParams || vault.kdf_params;
						break; // Keluar dari loop jika ditemukan yang cocok
					}

				} catch (error) {
					// PERBAIKAN: JANGAN hide spinner di sini. 
					// Biarkan loop berlanjut ke vault berikutnya.
					console.debug('Vault identity mismatch untuk vault_id:', vault.vault_id);
					continue;
				} finally {
					// Pembersihan memori sensitif tiap iterasi
					if (derivedKeys) {
						try {
							this.zeroizeUint8(derivedKeys.rawEncKey);
							this.zeroizeUint8(derivedKeys.rawAuthKey);
						} catch (e) {
							console.error('Zeroization error:', e);
						}
					}
				}
			}

			// 3. Evaluasi Hasil Akhir
			if (unlockedVault && foundEncCryptoKey) {
				this.resetFailedAttempts();

				this.cryptoBoundary = {
					encCryptoKey: foundEncCryptoKey,
					authCryptoKey: foundAuthCryptoKey,
					kdfParams: foundKdfParams
				};

				this.currentVaultId = unlockedVault.vault_id;
				this.currentVault = unlockedVault;

				const registry = JSON.parse(localStorage.getItem('safevault_registry'));
				registry.active_vault_id = unlockedVault.vault_id;
				localStorage.setItem('safevault_registry', JSON.stringify(registry));

				this.broadcast({
					type: 'VAULT_UNLOCKED',
					vaultId: unlockedVault.vault_id
				});

				// Pindah ke dalam vault
				await this.enterVault();

			} else {
				// Jika tidak ada satu pun vault yang cocok
				this.recordFailedAttempt();
				this.clearCryptoBoundary();

				this.showScreen('createVaultScreen');
				this.elements.newMasterPassword.value = password;
				this.updatePasswordStrength(password);
				this.validatePasswordMatch();

				this.showToast(
					'Password tidak mengidentifikasi vault yang ada. Buat vault baru?',
					'info'
				);
			}

		} catch (error) {
			console.error('Unlock flow failed:', error);
			this.clearCryptoBoundary();
			this.showScreen('lockScreen');
			this.showToast('Proses verifikasi gagal', 'danger');
		} finally {
			// 4. LOGIKA FINAL: Spinner ditutup di sini
			// Menangani semua skenario: Berhasil, Password Salah, atau Error Sistem.
			this.hideOverlaySpinner();
		}
	},

	// ===========================================
	// VAULT CREATION
	// ===========================================
	createNewVault: async function() {
		const password = this.elements.newMasterPassword?.value;
		const confirm = this.elements.confirmMasterPassword?.value;
		const name = this.elements.vaultName?.value || 'Vault Utama';
		const hint = this.elements.passwordHint?.value || '';

		// 1. Validasi awal (dilakukan sebelum spinner muncul)
		if (!password || password.length < 8) {
			this.showToast('Password minimal 8 karakter', 'warning');
			return;
		}

		if (password !== confirm) {
			this.showToast('Password tidak cocok', 'warning');
			return;
		}

		// 2. Tampilkan Spinner tepat sebelum proses berat dimulai
		this.showOverlaySpinner('Membuat identitas vault baru...');
		await this.yieldToUI();

		try {
			// Generate Unique ID
			const vaultId = 'vault_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

			// Generate Salt untuk KDF
			const salt = crypto.getRandomValues(new Uint8Array(this.CRYPTO.KDF_SALT_LENGTH));

			// Derivasi Key dari Password
			const derivedKeys = await this.deriveKeys(password, salt);

			// Import kunci untuk operasi kriptografi
			const encCryptoKey = await this.importAesKeyFromRaw(
				derivedKeys.rawEncKey,
				['encrypt', 'decrypt']
			);

			const authCryptoKey = await this.importHmacKeyFromRaw(
				derivedKeys.rawAuthKey
			);

			// Keamanan: Hapus raw key dari memori segera setelah di-import
			this.zeroizeUint8(derivedKeys.rawEncKey);
			this.zeroizeUint8(derivedKeys.rawAuthKey);

			// Set ke boundary aplikasi
			this.cryptoBoundary = {
				encCryptoKey,
				authCryptoKey,
				kdfParams: derivedKeys.kdfParams
			};

			// Membuat "Magic Bytes" terenkripsi untuk verifikasi password di masa depan
			const magicBytes = this.MAGIC_BYTES;
			const encryptedMagic = await this.encryptData(magicBytes, encCryptoKey);

			const iv = encryptedMagic.iv;
			const ciphertext = new Uint8Array(encryptedMagic.ciphertext);

			const combined = new Uint8Array(this.CRYPTO.IV_LENGTH + ciphertext.length);
			combined.set(iv, 0);
			combined.set(ciphertext, this.CRYPTO.IV_LENGTH);

			const magicBase64 = this.arrayBufferToBase64(combined.buffer);

			// Susun objek Vault
			const vault = {
				vault_id: vaultId,
				name: name,
				salt: this.uint8ArrayToHex(salt),
				kdf_params: derivedKeys.kdfParams,
				key_check_encrypted: magicBase64,
				created_at: new Date().toISOString(),
				last_accessed: new Date().toISOString(),
				item_count: 0,
				schema_version: 3
			};

			// Penanganan Hint (Opsional)
			if (hint) {
				try {
					const encryptedHint = await this.encryptData(hint, encCryptoKey);

					const combinedHint = new Uint8Array(
						this.CRYPTO.IV_LENGTH + encryptedHint.ciphertext.byteLength
					);
					combinedHint.set(encryptedHint.iv, 0);
					combinedHint.set(new Uint8Array(encryptedHint.ciphertext), this.CRYPTO.IV_LENGTH);

					vault.password_hint_encrypted = this.arrayBufferToBase64(combinedHint.buffer);

					this.zeroizeString(hint);

				} catch (hintError) {
					// Jika hint gagal, proses utama tetap lanjut, hanya log peringatan
					console.warn('Gagal mengenkripsi hint:', hintError);
				}
			}

			// Simpan ke storage
			await this.saveVault(vault);

			// Update Registry aplikasi
			const registry = JSON.parse(localStorage.getItem('safevault_registry'));
			registry.vault_ids.push(vaultId);
			registry.active_vault_id = vaultId;
			registry.onboarding_completed = true;
			localStorage.setItem('safevault_registry', JSON.stringify(registry));

			this.currentVaultId = vaultId;
			this.currentVault = vault;

			// Beritahu sistem bahwa vault berhasil dibuat
			this.broadcast({
				type: 'VAULT_CREATED',
				vaultId: vaultId
			});

			// Masuk ke dalam vault
			await this.enterVault();

		} catch (error) {
			// Tangani jika terjadi kegagalan sistem/kriptografi
			console.error('Vault creation failed:', error);
			this.clearCryptoBoundary();
			this.showScreen('createVaultScreen');
			this.showToast('Gagal membuat vault', 'danger');
		} finally {
			// 3. TUTUP SPINNER (Apapun hasilnya, sukses atau gagal)
			// Ini menjamin UI tidak terkunci/hang bagi user.
			this.hideOverlaySpinner();
		}
	},


	// ===========================================
	// VAULT OPERATIONS
	// ===========================================
	enterVault: async function() {
		await this.loadVaultItems();
		this.updateVaultInfo();
		this.showScreen('mainApp');
		this.startAutoLockTimer();
		this.showTimerDisplay();

		// Request notification permission
		if ('Notification' in window && Notification.permission === 'default') {
			Notification.requestPermission();
		}

		this.showToast(`Selamat datang di ${this.currentVault.name}`, 'success');
	},

	updateLoadingText: function(text, subtext = '') {
		const loadingScreen = this.elements.loadingScreen;
		if (!loadingScreen) return;

		const title = loadingScreen.querySelector('.loading-title');
		const subtitle = loadingScreen.querySelector('.loading-subtitle');

		if (title) title.textContent = text;
		if (subtitle && subtext) subtitle.textContent = subtext;
	},

	loadVaultItems: async function() {
		try {
			this.updateLoadingText('Memuat item vault...', 'Dekripsi data aman');

			const encryptedItems = await this.getVaultItems(this.currentVaultId);

			if (!this.cryptoBoundary.encCryptoKey) {
				throw new Error('Crypto key not available');
			}

			this.currentVaultItems = [];
			let successCount = 0;
			let errorCount = 0;

			for (const item of encryptedItems) {
				try {
					let metadata = {};

					const encryptedPayload = this.base64ToUint8Array(item.encrypted_payload);
					const iv = encryptedPayload.slice(0, this.CRYPTO.IV_LENGTH);
					const ciphertext = encryptedPayload.slice(this.CRYPTO.IV_LENGTH).buffer;

					const decryptedBytes = await this.decryptData(
						iv,
						ciphertext,
						this.cryptoBoundary.encCryptoKey
					);
					const decryptedText = new TextDecoder().decode(decryptedBytes);

					if (item.meta_encrypted) {
						const encryptedMeta = this.base64ToUint8Array(item.meta_encrypted);
						const metaIv = encryptedMeta.slice(0, this.CRYPTO.IV_LENGTH);
						const metaCiphertext = encryptedMeta.slice(this.CRYPTO.IV_LENGTH).buffer;
						const metaBytes = await this.decryptData(metaIv, metaCiphertext, this.cryptoBoundary.encCryptoKey);
						const metaJson = new TextDecoder().decode(metaBytes);
						try {
							metadata = JSON.parse(metaJson);
						} catch (e) {
							metadata = {};
						}
					}

					this.currentVaultItems.push({
						id: item.item_id,
						label: metadata.label || 'Tanpa Label',
						value: decryptedText,
						category: metadata.category || 'Uncategorized',
						tags: metadata.tags || [],
						created_at: item.created_at,
						updated_at: item.updated_at
					});

					successCount++;

				} catch (error) {
					console.error('Failed to decrypt item:', item.item_id, error);
					errorCount++;

					this.currentVaultItems.push({
						id: item.item_id,
						corrupted: true,
						label: 'Item Rusak',
						value: null,
						error: error.message
					});
				}
			}

			this.renderItemsList();

			if (errorCount > 0) {
				this.showToast(
					`Memuat ${successCount} item, ${errorCount} gagal`,
					'warning'
				);
			} else if (successCount > 0) {
				this.showToast(
					`Berhasil memuat ${successCount} item`,
					'success'
				);
			}

		} catch (error) {
			console.error('Failed to load vault items:', error);
			this.showToast('Gagal memuat item vault', 'danger');
			throw error;
		}
	},

	saveItem: async function() {
		const label = this.elements.itemLabel?.value.trim();
		const value = this.elements.itemValue?.value.trim();
		const category = this.getSelectedCategory();
		const tags = this.getSelectedTags();

		if (!label || !value) {
			this.showToast('Label dan nilai harus diisi', 'warning');
			return;
		}

		try {
			if (!this.cryptoBoundary.encCryptoKey) {
				throw new Error('Encryption key not available');
			}

			const metadata = {
				label: label,
				category: category,
				tags: tags,
				created: new Date().toISOString()
			};

			const encryptedValue = await this.encryptData(value, this.cryptoBoundary.encCryptoKey);
			const valueForStorage = new Uint8Array(
				encryptedValue.iv.length + encryptedValue.ciphertext.byteLength
			);
			valueForStorage.set(encryptedValue.iv);
			valueForStorage.set(new Uint8Array(encryptedValue.ciphertext), encryptedValue.iv.length);

			const encryptedMeta = await this.encryptData(JSON.stringify(metadata), this.cryptoBoundary.encCryptoKey);
			const metaForStorage = new Uint8Array(
				encryptedMeta.iv.length + encryptedMeta.ciphertext.byteLength
			);
			metaForStorage.set(encryptedMeta.iv);
			metaForStorage.set(new Uint8Array(encryptedMeta.ciphertext), encryptedMeta.iv.length);

			let hmacSignature = null;
			if (this.cryptoBoundary.authCryptoKey) {
				const signature = await crypto.subtle.sign({
						name: 'HMAC',
						hash: {
							name: 'SHA-256'
						}
					},
					this.cryptoBoundary.authCryptoKey,
					valueForStorage
				);
				hmacSignature = this.arrayBufferToBase64(signature);
			}

			const item = {
				vault_id: this.currentVaultId,
				encrypted_payload: this.arrayBufferToBase64(valueForStorage),
				meta_encrypted: this.arrayBufferToBase64(metaForStorage),
				hmac_signature: hmacSignature,
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
				item_version: 3
			};

			const itemId = await this.saveItemToDB(item);

			this.currentVaultItems.unshift({
				id: itemId,
				label: label,
				value: value,
				category: category,
				tags: tags,
				created_at: item.created_at
			});

			this.renderItemsList();
			this.clearItemForm();

			this.broadcast({
				type: 'ITEM_ADDED',
				vaultId: this.currentVaultId,
				itemId: itemId
			});

			this.showToast('Item berhasil disimpan', 'success');

		} catch (error) {
			console.error('Failed to save item:', error);
			this.showToast('Gagal menyimpan item', 'danger');
		}
	},

	// ===========================================
	// SECURITY MANAGEMENT
	// ===========================================
	clearCryptoBoundary: function() {
		console.log('Clearing crypto boundary...');

		if (this.cryptoBoundary.rawEncKey instanceof Uint8Array) {
			this.zeroizeUint8(this.cryptoBoundary.rawEncKey);
		}

		if (this.cryptoBoundary.rawAuthKey instanceof Uint8Array) {
			this.zeroizeUint8(this.cryptoBoundary.rawAuthKey);
		}

		this.cryptoBoundary.encCryptoKey = null;
		this.cryptoBoundary.authCryptoKey = null;
		this.cryptoBoundary.kdfParams = null;

		this.lockUntil = null;
	},

	lockApp: function() {
		this.broadcast({
			type: 'VAULT_LOCKED'
		});

		this.clearClipboardNow();

		this.clearAllTimers();

		this.clearCryptoBoundary();

		this.currentVault = null;
		this.currentVaultId = null;
		this.currentVaultItems = [];

		const registry = JSON.parse(localStorage.getItem('safevault_registry'));
		registry.active_vault_id = null;
		localStorage.setItem('safevault_registry', JSON.stringify(registry));

		this.showScreen('lockScreen');
		this.elements.masterPassInput.value = '';
		this.elements.masterPassInput.focus();

		this.hideTimerDisplay();

		console.log('App locked');
	},

	// ===========================================
	// EVENT LISTENERS SETUP
	// ===========================================
	setupEventListeners: function() {
		// Lock screen
		this.elements.masterPassInput?.addEventListener('keypress', (e) => {
			if (e.key === 'Enter') this.attemptUnlock();
		});

		// Auto-lock reset
		['mousedown', 'keydown', 'touchstart'].forEach(event => {
			document.addEventListener(event, () => this.resetAutoLockTimer());
		});

		// Create vault validation
		this.elements.newMasterPassword?.addEventListener('input', (e) => {
			this.updatePasswordStrength(e.target.value);
		});

		this.elements.confirmMasterPassword?.addEventListener('input', () => {
			this.validatePasswordMatch();
		});

		// Import/export
		const importFileInput = document.getElementById('importFileInput');
		if (importFileInput) {
			importFileInput.addEventListener('change', (e) => {
				this.handleImportFile(e);
			});
		}

		const exportPasswordInput = document.getElementById('exportPassword');
		if (exportPasswordInput) {
			exportPasswordInput.addEventListener('keypress', (e) => {
				if (e.key === 'Enter') {
					this.performExport();
				}
			});
		}

		// Category input
		const categoryInput = document.getElementById('itemCategory');
		if (categoryInput) {
			categoryInput.addEventListener('keypress', (e) => {
				if (e.key === 'Enter') {
					e.preventDefault();
					this.addCategoryTag(e.target.value);
					e.target.value = '';
				}
			});
		}

		// Search
		this.setupSearchListener();

		// Modal close
		document.addEventListener('click', (e) => {
			if (e.target.classList.contains('modal-overlay')) {
				const modal = e.target.closest('.modal-overlay');
				if (modal) {
					this.hideModal(modal.id);
				}
			}
		});
	},

	// ===========================================
	// AUTO-LOCK TIMER SYSTEM
	// ===========================================
	startAutoLockTimer: function() {
		this.clearAllTimers();

		const duration = this.config.autoLockMinutes * 60 * 1000;
		this.lockUntil = Date.now() + duration;

		this.timerInterval = setInterval(() => {
			const remaining = Math.max(0, this.lockUntil - Date.now());
			const seconds = Math.floor(remaining / 1000);

			this.updateTimerUI(seconds);

			if (remaining <= 0) {
				this.lockApp();
			} else if (seconds === 10) {
				this.showAutoLockWarning();
			}
		}, 1000);
	},

	resetAutoLockTimer: function() {
		if (this.currentVaultId) {
			this.startAutoLockTimer();
			this.hideAutoLockWarning();
		}
	},

	clearAllTimers: function() {
		if (this.timerInterval) clearInterval(this.timerInterval);
		if (this.timers.autoLockWarning) clearTimeout(this.timers.autoLockWarning);
		if (this.timers.clipboard) clearTimeout(this.timers.clipboard);
	},

	updateTimerUI: function(totalSeconds) {
		const minutes = Math.floor(totalSeconds / 60);
		const seconds = totalSeconds % 60;
		const display = `${minutes}:${seconds.toString().padStart(2, '0')}`;

		const timerText = document.getElementById('timerText');
		const countdownText = document.getElementById('countdownText');
		const progressCircle = document.querySelector('.countdown-progress');

		if (timerText) timerText.textContent = `Auto-lock: ${display}`;
		if (countdownText) countdownText.textContent = totalSeconds;

		if (progressCircle) {
			const total = this.config.autoLockMinutes * 60;
			const offset = 100 - (totalSeconds / total * 100);
			progressCircle.style.strokeDashoffset = offset;
		}
	},

	// ===========================================
	// UI UTILITIES
	// ===========================================
	showToast: function(message, type = 'info') {
		const container = document.getElementById('toastContainer');
		const toast = document.createElement('div');
		toast.className = `toast show ${type}`;
		toast.innerHTML = `
            <div class="toast-content">
                <i class="ph ph-info toast-icon"></i>
                <span>${message}</span>
            </div>
        `;
		container.appendChild(toast);

		setTimeout(() => {
			toast.classList.remove('show');
			setTimeout(() => toast.remove(), 500);
		}, 3000);
	},

	showTimerDisplay: function() {
		const el = document.getElementById('timerDisplay');
		if (el) el.classList.add('show');
	},

	hideTimerDisplay: function() {
		const el = document.getElementById('timerDisplay');
		if (el) el.classList.remove('show');
	},

	showAutoLockWarning: function() {
		const el = document.getElementById('autoLockWarning');
		if (el) el.classList.add('show');
	},

	hideAutoLockWarning: function() {
		const el = document.getElementById('autoLockWarning');
		if (el) el.classList.remove('show');
	},

	// ===========================================
	// MULTI-TAB SYNC
	// ===========================================
	initMultiTabSync: function() {
		try {
			this.broadcastChannel = new BroadcastChannel('safevault_sync');

			this.broadcastChannel.onmessage = (event) => {
				const {
					type,
					vaultId
				} = event.data;

				switch (type) {
					case 'VAULT_LOCKED':
						if (this.currentVaultId) this.lockApp();
						break;
					case 'VAULT_UNLOCKED':
						if (!this.currentVaultId) {
							this.showToast('Vault dibuka di tab lain', 'info');
						}
						break;
				}
			};
		} catch (e) {
			console.warn('BroadcastChannel tidak didukung');
		}
	},

	broadcast: function(data) {
		if (this.broadcastChannel) {
			this.broadcastChannel.postMessage(data);
		}
	},

	// ===========================================
	// FORM MANAGEMENT
	// ===========================================
	clearItemForm: function() {
		if (this.elements.itemLabel) this.elements.itemLabel.value = '';
		if (this.elements.itemValue) this.elements.itemValue.value = '';
		if (document.getElementById('itemCategory')) document.getElementById('itemCategory').value = '';
		if (document.getElementById('itemTags')) document.getElementById('itemTags').value = '';

		const tagContainer = document.getElementById('tagContainer');
		if (tagContainer) tagContainer.innerHTML = '';
	},

	getSelectedCategory: function() {
		return document.getElementById('itemCategory')?.value || 'General';
	},

	getSelectedTags: function() {
		const tagInput = document.getElementById('itemTags')?.value;
		if (!tagInput) return [];
		return tagInput.split(',').map(t => t.trim()).filter(t => t !== '');
	},

	updateVaultInfo: function() {
		const nameEl = document.getElementById('currentVaultName');
		const countEl = document.getElementById('itemCount');

		if (nameEl) nameEl.textContent = this.currentVault?.name || 'Unknown Vault';
		if (countEl) countEl.textContent = `${this.currentVaultItems.length} item`;
	},

	// ===========================================
	// SECURITY CHECKS
	// ===========================================
	canAttemptUnlock: function() {
		const failedAttempts = parseInt(localStorage.getItem('safevault_failed_attempts') || '0');
		const lastAttempt = parseInt(localStorage.getItem('safevault_last_attempt') || '0');

		if (failedAttempts >= this.config.maxFailedAttempts) {
			const waitTime = Math.min(
				this.config.backoffBaseMs * Math.pow(2, failedAttempts - this.config.maxFailedAttempts),
				this.config.backoffMaxMs
			);
			const remaining = (lastAttempt + waitTime) - Date.now();

			if (remaining > 0) {
				this.showToast(`Terlalu banyak percobaan. Tunggu ${Math.ceil(remaining/1000)} detik.`, 'warning');
				return false;
			}
		}
		return true;
	},

	recordFailedAttempt: function() {
		const failed = parseInt(localStorage.getItem('safevault_failed_attempts') || '0') + 1;
		localStorage.setItem('safevault_failed_attempts', failed.toString());
		localStorage.setItem('safevault_last_attempt', Date.now().toString());
		this.showToast('Password salah!', 'danger');
	},

	resetFailedAttempts: function() {
		localStorage.setItem('safevault_failed_attempts', '0');
	},

	updatePasswordStrength: function(password) {
		if (!password) return;

		const result = zxcvbn ? zxcvbn(password) : {
			score: 0
		};
		const score = result.score;

		const levels = [{
				color: 'var(--danger)',
				label: 'Sangat Lemah',
				width: '20%'
			},
			{
				color: 'var(--danger)',
				label: 'Lemah',
				width: '40%'
			},
			{
				color: 'var(--warning)',
				label: 'Cukup',
				width: '60%'
			},
			{
				color: 'var(--info)',
				label: 'Kuat',
				width: '80%'
			},
			{
				color: 'var(--success)',
				label: 'Sangat Kuat',
				width: '100%'
			}
		];

		const current = levels[score];
		const fill = document.getElementById('strengthMeterFill');
		const text = document.getElementById('strengthText');

		if (fill) {
			fill.style.width = current.width;
			fill.style.background = current.color;
		}
		if (text) text.textContent = current.label;

		this.validatePasswordMatch();
	},

	validatePasswordMatch: function() {
		const p1 = this.elements.newMasterPassword?.value;
		const p2 = this.elements.confirmMasterPassword?.value;
		const btn = document.getElementById('createVaultButton');
		const hint = document.getElementById('confirmHint');

		const isMatch = p1 === p2 && p1.length >= 8;

		if (btn) btn.disabled = !isMatch;

		if (hint && p2.length > 0) {
			hint.textContent = isMatch ? 'Password cocok' : 'Password belum cocok';
			hint.className = `input-hint mt-sm ${isMatch ? 'success' : 'error'}`;
		}
	},

	// ===========================================
	// CLIPBOARD MANAGEMENT
	// ===========================================
	copyToClipboard: async function(text) {
		try {
			await navigator.clipboard.writeText(text);
			this.showToast('Berhasil disalin! Clipboard akan dihapus dalam 30 detik.', 'success');
			this.startClipboardTimer();
		} catch (error) {
			console.error('Failed to copy to clipboard:', error);
			this.showToast('Gagal menyalin ke clipboard', 'danger');
		}
	},

	startClipboardTimer: function() {
		if (this.timers.clipboard) {
			clearTimeout(this.timers.clipboard);
		}

		const overlay = document.getElementById('clipboardOverlay');
		if (overlay) {
			overlay.classList.add('active');
		}

		let timeLeft = this.config.clipboardTimeout;
		const countdownText = document.getElementById('clipboardCountdownText');
		const progressCircle = document.getElementById('clipboardProgressCircle');

		const countdownInterval = setInterval(() => {
			timeLeft--;

			if (countdownText) {
				countdownText.textContent = timeLeft;
			}

			if (progressCircle) {
				const total = this.config.clipboardTimeout;
				const offset = 100 - (timeLeft / total * 100);
				progressCircle.style.strokeDashoffset = offset;
			}

			if (timeLeft <= 0) {
				clearInterval(countdownInterval);
				this.clearClipboardNow();
			}
		}, 1000);

		this.timers.clipboard = setTimeout(() => {
			clearInterval(countdownInterval);
			this.clearClipboardNow();
		}, this.config.clipboardTimeout * 1000);
	},

	clearClipboardNow: function() {
		navigator.clipboard.writeText('');
		document.getElementById('clipboardOverlay')?.classList.remove('active');
		this.showToast('Clipboard dibersihkan', 'info');
	},

	keepClipboardData: function() {
		if (this.timers.clipboard) {
			clearTimeout(this.timers.clipboard);
			this.timers.clipboard = null;
		}

		const overlay = document.getElementById('clipboardOverlay');
		if (overlay) {
			overlay.classList.remove('active');
		}

		this.showToast('Clipboard data dipertahankan', 'info');
	},

	// ===========================================
	// PASSWORD VISIBILITY TOGGLE
	// ===========================================
	togglePasswordVisibility: function(inputId) {
		const input = document.getElementById(inputId);
		if (input) {
			input.type = input.type === 'password' ? 'text' : 'password';
		}
	},

	// ===========================================
	// SEARCH FUNCTIONALITY
	// ===========================================
	filterItems: function(query) {
		if (!query || query.trim() === '') {
			this.renderItemsList();
			return;
		}

		const filtered = this.enhancedSearch(query);
		this.renderItemsList(filtered);
	},

	enhancedSearch: function(query) {
		const terms = query.toLowerCase().split(/\s+/).filter(term => term.length > 0);

		return this.currentVaultItems.map(item => {
				let score = 0;
				const label = item.label.toLowerCase();
				const category = (item.category || '').toLowerCase();
				const tags = (item.tags || []).map(tag => tag.toLowerCase());
				const value = (item.value || '').toLowerCase();

				if (label === query.toLowerCase()) score += 20;
				if (category === query.toLowerCase()) score += 15;

				terms.forEach(term => {
					if (label.includes(term)) score += 10;
					if (category.includes(term)) score += 8;
					if (tags.some(tag => tag.includes(term))) score += 5;
					if (value.includes(term)) score += 3;
				});

				const created = new Date(item.created_at);
				const daysOld = (Date.now() - created) / (1000 * 60 * 60 * 24);
				if (daysOld < 7) score += 2;

				return {
					item,
					score
				};
			})
			.filter(result => result.score > 0)
			.sort((a, b) => b.score - a.score)
			.map(result => result.item);
	},

	clearSearch: function() {
		const searchInput = document.getElementById('searchInput');
		const clearBtn = document.getElementById('clearSearchBtn');

		if (searchInput) {
			searchInput.value = '';
			searchInput.focus();
			this.renderItemsList();
		}

		if (clearBtn) {
			clearBtn.style.display = 'none';
		}
	},

	setupSearchListener: function() {
		const searchInput = document.getElementById('searchInput');
		const clearBtn = document.getElementById('clearSearchBtn');

		if (!searchInput) return;

		let searchTimeout;

		searchInput.addEventListener('input', (e) => {
			if (clearBtn) {
				clearBtn.style.display = e.target.value ? 'flex' : 'none';
			}

			clearTimeout(searchTimeout);
			searchTimeout = setTimeout(() => {
				this.filterItems(e.target.value);
			}, 300);
		});

		searchInput.addEventListener('keypress', (e) => {
			if (e.key === 'Enter') {
				clearTimeout(searchTimeout);
				this.filterItems(e.target.value);
			}
		});

		if (clearBtn) {
			clearBtn.addEventListener('click', () => {
				SafeVault.clearSearch();
				searchInput.focus();
				clearBtn.style.display = 'none';
			});
		}
	},

	// ===========================================
	// SORTING SYSTEM
	// ===========================================
	toggleSort: function() {
		const sortState = localStorage.getItem('safevault_sort') || 'newest';
		let newSort;

		switch (sortState) {
			case 'newest':
				newSort = 'oldest';
				break;
			case 'oldest':
				newSort = 'az';
				break;
			case 'az':
				newSort = 'za';
				break;
			case 'za':
				newSort = 'newest';
				break;
			default:
				newSort = 'newest';
		}

		localStorage.setItem('safevault_sort', newSort);
		this.applySort(newSort);
		this.showToast(`Diurutkan: ${this.getSortLabel(newSort)}`, 'info');
	},

	getSortLabel: function(sortKey) {
		const labels = {
			'newest': 'Terbaru',
			'oldest': 'Terlama',
			'az': 'A-Z',
			'za': 'Z-A'
		};
		return labels[sortKey] || 'Terbaru';
	},

	applySort: function(sortKey) {
		if (!this.currentVaultItems || this.currentVaultItems.length === 0) return;

		const sorted = [...this.currentVaultItems];

		switch (sortKey) {
			case 'newest':
				sorted.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
				break;
			case 'oldest':
				sorted.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
				break;
			case 'az':
				sorted.sort((a, b) => a.label.localeCompare(b.label));
				break;
			case 'za':
				sorted.sort((a, b) => b.label.localeCompare(a.label));
				break;
		}

		this.renderItemsList(sorted);
	},

	initSort: function() {
		const sortState = localStorage.getItem('safevault_sort') || 'newest';
		this.applySort(sortState);
	},

	// ===========================================
	// HTML ESCAPING
	// ===========================================
	escapeHTML: function(str) {
		if (!str) return '';

		const htmlEscapes = {
			'&': '&amp;',
			'<': '&lt;',
			'>': '&gt;',
			'"': '&quot;',
			"'": '&#39;',
			'/': '&#x2F;',
			'`': '&#96;'
		};

		const reEscapable = /[&<>"'`\/]/g;

		return String(str).replace(reEscapable, (match) => {
			return htmlEscapes[match];
		});
	},

	sanitizeForAttribute: function(str) {
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#x27;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;');
	},

	// ===========================================
	// ITEM LIST RENDERING
	// ===========================================
	renderItemsList: function(items = this.currentVaultItems) {
		const container = document.getElementById('itemsListContainer');
		const emptyState = document.getElementById('emptyState');
		if (!container) return;

		container.innerHTML = '';

		if (items.length === 0) {
			emptyState.style.display = 'block';
			return;
		}

		emptyState.style.display = 'none';

		items.forEach(item => {
			const itemEl = document.createElement('div');
			itemEl.className = 'list-item animate-fade-in';
			itemEl.innerHTML = `
                <div class="list-item-content">
                    <div class="list-item-title">${this.escapeHTML(item.label)}</div>
                    <div class="list-item-meta">
                        <span class="tag"><i class="ph ph-tag"></i> ${this.escapeHTML(item.category)}</span>
                    </div>
                </div>
                <div class="flex gap-xs">
                    <button class="icon-button small" onclick="SafeVault.copyToClipboard('${this.sanitizeForAttribute(item.value)}')">
                        <i class="ph ph-copy"></i>
                    </button>
                    <button class="icon-button small danger" onclick="SafeVault.deleteItem('${item.id}')">
                        <i class="ph ph-trash"></i>
                    </button>
                </div>
            `;
			container.appendChild(itemEl);
		});

		this.updateVaultInfo();
	},

	refreshItems: async function() {
		if (!this.currentVaultId) return;

		this.showToast('Memuat ulang item...', 'info');
		await this.loadVaultItems();
		this.showToast('Item diperbarui', 'success');
	},

	// ===========================================
	// ITEM DELETE OPERATIONS
	// ===========================================
	deleteItem: async function(itemId) {
		const item = this.currentVaultItems.find(i => i.id === itemId);

		if (!item) {
			this.showToast('Item tidak ditemukan', 'warning');
			return;
		}

		this.showDeleteConfirmation(itemId, item.label);
	},

	showDeleteConfirmation: function(itemId, itemLabel) {
		const labelEl = document.getElementById('deleteItemLabel');
		if (labelEl) {
			labelEl.textContent = `Anda akan menghapus "${itemLabel}" secara permanen`;
		}

		const modal = document.getElementById('deleteModal');
		if (modal) {
			modal.dataset.itemId = itemId;
			this.showModal('deleteModal');
		}
	},

	confirmDelete: async function() {
		const deleteModal = document.getElementById('deleteModal');
		const itemId = deleteModal.dataset.itemId;

		if (!itemId) {
			this.hideModal('deleteModal');
			return;
		}

		try {
			await this.deleteItemFromDB(itemId);

			this.currentVaultItems = this.currentVaultItems.filter(i => i.id !== itemId);

			this.renderItemsList();

			this.hideModal('deleteModal');
			this.showToast('Item berhasil dihapus', 'success');

			this.broadcast({
				type: 'ITEM_DELETED',
				vaultId: this.currentVaultId,
				itemId: itemId
			});

		} catch (error) {
			console.error('Failed to delete item:', error);
			this.showToast('Gagal menghapus item', 'danger');
		}
	},

	// ===========================================
	// EXPORT/IMPORT OPERATIONS
	// ===========================================
	performExport: async function() {
		const exportPassword = document.getElementById('exportPassword')?.value || null;

		try {
			this.showToast('Mempersiapkan export...', 'info');

			if (!this.currentVaultId) {
				throw new Error('Tidak ada vault yang aktif');
			}

			const vault = await this.getVaultFromDB(this.currentVaultId);
			const items = await this.getVaultItems(this.currentVaultId);

			let backupData = {
				version: "2.4",
				export_date: new Date().toISOString(),
				vault_metadata: {
					name: vault.name,
					salt: vault.salt,
					kdf_params: vault.kdf_params,
					key_check_encrypted: vault.key_check_encrypted,
					password_hint_encrypted: vault.password_hint_encrypted,
					created_at: vault.created_at
				},
				items: items
			};

			if (exportPassword) {
				this.showToast('Mengenkripsi backup...', 'info');

				const salt = crypto.getRandomValues(new Uint8Array(16));

				const derivedKeys = await this.deriveKeys(exportPassword, salt);
				const exportEncKey = await this.importAesKeyFromRaw(derivedKeys.rawEncKey);

				const encrypted = await this.encryptData(
					JSON.stringify(backupData),
					exportEncKey
				);

				const combined = new Uint8Array(
					salt.length + encrypted.iv.length + encrypted.ciphertext.byteLength
				);
				combined.set(salt, 0);
				combined.set(encrypted.iv, salt.length);
				combined.set(new Uint8Array(encrypted.ciphertext), salt.length + encrypted.iv.length);

				backupData = {
					encrypted: true,
					version: "2.4-encrypted",
					salt: this.arrayBufferToBase64(salt),
					iv: this.arrayBufferToBase64(encrypted.iv),
					ciphertext: this.arrayBufferToBase64(encrypted.ciphertext)
				};

				this.zeroizeUint8(derivedKeys.rawEncKey);
				this.zeroizeUint8(derivedKeys.rawAuthKey);
			}

			const blob = new Blob([JSON.stringify(backupData, null, 2)], {
				type: 'application/json'
			});

			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			const timestamp = new Date().toISOString().split('T')[0];
			const vaultName = vault.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();

			a.href = url;
			a.download = `safevault_${vaultName}_${timestamp}.json`;
			document.body.appendChild(a);
			a.click();

			setTimeout(() => {
				document.body.removeChild(a);
				URL.revokeObjectURL(url);
			}, 100);

			this.hideModal('exportModal');
			this.showToast('Export berhasil!', 'success');

		} catch (error) {
			console.error('Export failed:', error);
			this.showToast(`Export gagal: ${error.message}`, 'danger');
		}
	},

	handleImportFile: async function(event) {
		const file = event.target.files[0];
		if (!file) return;

		const importPassword = document.getElementById('importPassword')?.value || '';

		try {
			this.showToast('Memproses file...', 'info');

			const fileContent = await this.readFileAsText(file);
			let importedData = JSON.parse(fileContent);

			if (importedData.encrypted) {
				this.showToast('Mendekripsi backup...', 'info');

				if (!importPassword) {
					throw new Error('File terenkripsi memerlukan password');
				}

				const salt = this.base64ToUint8Array(importedData.salt);
				const iv = this.base64ToUint8Array(importedData.iv);
				const ciphertext = this.base64ToUint8Array(importedData.ciphertext);

				const derivedKeys = await this.deriveKeys(importPassword, salt);
				const importEncKey = await this.importAesKeyFromRaw(derivedKeys.rawEncKey);

				const decryptedBytes = await this.decryptData(iv, ciphertext.buffer, importEncKey);
				const decryptedText = new TextDecoder().decode(decryptedBytes);
				importedData = JSON.parse(decryptedText);

				this.zeroizeUint8(derivedKeys.rawEncKey);
				this.zeroizeUint8(derivedKeys.rawAuthKey);
			}

			if (!importedData.vault_metadata || !importedData.items) {
				throw new Error('Format backup tidak valid');
			}

			const vaultId = 'vault_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
			const vault = {
				...importedData.vault_metadata,
				vault_id: vaultId,
				last_accessed: new Date().toISOString(),
				item_count: importedData.items.length
			};

			await this.saveVault(vault);

			for (const item of importedData.items) {
				const newItem = {
					...item,
					vault_id: vaultId,
					item_id: undefined
				};
				await this.saveItemToDB(newItem);
			}

			const registry = JSON.parse(localStorage.getItem('safevault_registry'));
			registry.vault_ids.push(vaultId);
			localStorage.setItem('safevault_registry', JSON.stringify(registry));

			this.hideModal('importModal');
			this.showToast('Import berhasil! Vault baru telah dibuat.', 'success');

			setTimeout(() => {
				location.reload();
			}, 1500);

		} catch (error) {
			console.error('Import failed:', error);
			this.showToast(`Import gagal: ${error.message}`, 'danger');
		}
	},

	readFileAsText: function(file) {
		return new Promise((resolve, reject) => {
			const reader = new FileReader();
			reader.onload = (e) => resolve(e.target.result);
			reader.onerror = (e) => reject(e);
			reader.readAsText(file);
		});
	},

	// ===========================================
	// CATEGORY MANAGEMENT
	// ===========================================
	addCategoryTag: function(category) {
		if (!category.trim()) return;

		const container = document.getElementById('categoryTags');
		if (!container) return;

		const existing = Array.from(container.children).find(tag =>
			tag.textContent.includes(category)
		);

		if (existing) {
			this.showToast('Kategori sudah ada', 'warning');
			return;
		}

		const tag = document.createElement('span');
		tag.className = 'tag';
		tag.innerHTML = `
            ${this.escapeHTML(category)}
            <button class="tag-remove" onclick="this.parentElement.remove()">
                <i class="ph ph-x"></i>
            </button>
        `;

		container.appendChild(tag);

		this.addToCategorySuggestions(category);
	},

	addToCategorySuggestions: function(category) {
		const datalist = document.getElementById('categorySuggestions');
		if (!datalist) return;

		const options = Array.from(datalist.options);
		const exists = options.some(opt => opt.value === category);

		if (!exists) {
			const option = document.createElement('option');
			option.value = category;
			datalist.appendChild(option);
		}
	},

	// ===========================================
	// VAULT SWITCHER
	// ===========================================
	showVaultSwitcher: function() {
		const switcher = document.getElementById('vaultSwitcher');
		const container = document.getElementById('vaultListContainer');

		if (switcher && container) {
			switcher.style.display = 'block';
			this.populateVaultList();

			setTimeout(() => {
				switcher.style.opacity = '1';
				switcher.style.transform = 'translateY(0)';
			}, 10);
		}
	},

	hideVaultSwitcher: function() {
		const switcher = document.getElementById('vaultSwitcher');
		if (switcher) {
			switcher.style.opacity = '0';
			switcher.style.transform = 'translateY(-10px)';

			setTimeout(() => {
				switcher.style.display = 'none';
			}, 300);
		}
	},

	populateVaultList: async function() {
		const container = document.getElementById('vaultListContainer');
		if (!container) return;

		try {
			const vaults = await this.getAllVaults();
			const currentVaultId = this.currentVaultId;

			container.innerHTML = '';

			if (vaults.length === 0) {
				container.innerHTML = '<p class="caption text-center">Belum ada vault</p>';
				return;
			}

			vaults.forEach(vault => {
				const vaultEl = document.createElement('div');
				vaultEl.className = `list-item ${vault.vault_id === currentVaultId ? 'active' : ''}`;
				vaultEl.innerHTML = `
                    <div class="list-item-content">
                        <div class="list-item-title">${this.escapeHTML(vault.name)}</div>
                        <div class="list-item-meta">
                            <span class="tag"><i class="ph ph-calendar"></i> ${new Date(vault.created_at).toLocaleDateString()}</span>
                            <span class="tag"><i class="ph ph-key"></i> ${vault.item_count || 0} items</span>
                        </div>
                    </div>
                    <div class="flex gap-xs">
                        <button class="icon-button small" onclick="SafeVault.switchVault('${vault.vault_id}')" 
                                ${vault.vault_id === currentVaultId ? 'disabled' : ''}>
                            <i class="ph ph-switch"></i>
                        </button>
                        <button class="icon-button small" onclick="SafeVault.showVaultOptions('${vault.vault_id}')">
                            <i class="ph ph-gear"></i>
                        </button>
                    </div>
                `;
				container.appendChild(vaultEl);
			});

		} catch (error) {
			console.error('Failed to populate vault list:', error);
			container.innerHTML = '<p class="caption error text-center">Gagal memuat vault</p>';
		}
	},

	switchVault: async function(vaultId) {
		if (vaultId === this.currentVaultId) {
			this.showToast('Vault sudah aktif', 'info');
			return;
		}

		this.showToast('Beralih vault...', 'info');
		await this.lockApp();
		this.showScreen('lockScreen');
	},

	// ===========================================
	// VAULT OPTIONS
	// ===========================================
	showVaultOptions: function(vaultId) {
		this.getAllVaults().then(vaults => {
			const targetVault = vaults.find(v => v.vault_id === vaultId);
			if (targetVault) {
				document.getElementById('vaultOptionsTitle').textContent = `Opsi: ${targetVault.name}`;
				window.currentVaultForOptions = vaultId;
				this.showModal('vaultOptionsModal');
			}
		});
	},

	renameVault: async function() {
		const vaultId = window.currentVaultForOptions;
		if (!vaultId) return;

		const newName = prompt('Masukkan nama baru untuk vault:', '');
		if (!newName || newName.trim() === '') return;

		try {
			const vault = await this.getVaultFromDB(vaultId);
			vault.name = newName.trim();
			vault.updated_at = new Date().toISOString();

			await this.saveVault(vault);

			if (this.currentVaultId === vaultId) {
				this.currentVault = vault;
				this.updateVaultInfo();
			}

			this.hideModal('vaultOptionsModal');
			this.showToast('Nama vault berhasil diubah', 'success');

			this.populateVaultList();

		} catch (error) {
			console.error('Failed to rename vault:', error);
			this.showToast('Gagal mengubah nama vault', 'danger');
		}
	},

	deleteVault: async function() {
		const vaultId = window.currentVaultForOptions;
		if (!vaultId) return;

		if (!confirm('Apakah Anda yakin ingin menghapus vault ini? Semua data akan hilang secara permanen.')) {
			return;
		}

		try {
			this.showToast('Menghapus vault...', 'info');

			await this.deleteAllVaultItems(vaultId);

			await this.deleteVaultFromDB(vaultId);

			const registry = JSON.parse(localStorage.getItem('safevault_registry'));
			registry.vault_ids = registry.vault_ids.filter(id => id !== vaultId);

			if (registry.active_vault_id === vaultId) {
				registry.active_vault_id = null;
			}

			localStorage.setItem('safevault_registry', JSON.stringify(registry));

			this.hideModal('vaultOptionsModal');
			this.showToast('Vault berhasil dihapus', 'success');

			if (this.currentVaultId === vaultId) {
				await this.lockApp();
			}

			this.populateVaultList();

		} catch (error) {
			console.error('Failed to delete vault:', error);
			this.showToast('Gagal menghapus vault', 'danger');
		}
	},

	// ===========================================
	// ONBOARDING FUNCTIONS
	// ===========================================
	nextOnboardingPage: function() {
		document.getElementById('onboardingPage1').style.display = 'none';
		document.getElementById('onboardingPage2').style.display = 'block';
		document.getElementById('onboardingPrev').style.display = 'inline-flex';
		document.getElementById('onboardingNext').style.display = 'none';
		document.getElementById('onboardingFinish').style.display = 'inline-flex';
		document.querySelectorAll('.onboarding-dot')[1].classList.add('active');
		document.querySelectorAll('.onboarding-dot')[0].classList.remove('active');
	},

	previousOnboardingPage: function() {
		document.getElementById('onboardingPage1').style.display = 'block';
		document.getElementById('onboardingPage2').style.display = 'none';
		document.getElementById('onboardingPrev').style.display = 'none';
		document.getElementById('onboardingNext').style.display = 'inline-flex';
		document.getElementById('onboardingFinish').style.display = 'none';
		document.querySelectorAll('.onboarding-dot')[0].classList.add('active');
		document.querySelectorAll('.onboarding-dot')[1].classList.remove('active');
	},

	finishOnboarding: function() {
		this.showScreen('createVaultScreen');
	},

	showCreateVaultScreen: function() {
		this.showScreen('createVaultScreen');
	},

	cancelCreateVault: function() {
		this.getAllVaults().then(hasVaults => {
			const target = hasVaults ? 'lockScreen' : 'onboardingScreen';
			this.showScreen(target);
		});
	},

	showSearch: function(e) {
		if (e) e.stopPropagation();

		const container = document.getElementById('searchContainer');
		const input = document.getElementById('searchInput');

		container.style.display = container.style.display === 'none' ? 'block' : 'none';
		if (container.style.display === 'block') document.getElementById('searchInput').focus();

		// pasang listener klik luar (sekali)
		document.addEventListener('click', this._handleSearchOutsideClick);
	},

	_handleSearchOutsideClick: function(e) {
		const container = document.getElementById('searchContainer');
		const toggleBtn = document.getElementById('searchToggle');

		if (!container) return;

		if (
			container.contains(e.target) ||
			toggleBtn?.contains(e.target)
		) {
			return; // klik di dalam → abaikan
		}

		// klik di luar → tutup
		container.style.display = 'none';
		document.removeEventListener('click', SafeVault._handleSearchOutsideClick);
	},

	// ===========================================
	// MODAL MANAGEMENT
	// ===========================================
	showModal: function(modalId) {
		const modal = document.getElementById(modalId);
		if (modal) {
			modal.classList.add('active');
			modal.style.display = 'flex';
			document.body.style.overflow = 'hidden';

			setTimeout(() => {
				modal.style.opacity = '1';
				modal.style.visibility = 'visible';
			}, 10);
		}
	},

	hideModal: function(modalId) {
		const modal = document.getElementById(modalId);
		if (modal) {
			modal.style.opacity = '0';
			modal.style.visibility = 'hidden';

			setTimeout(() => {
				modal.classList.remove('active');
				modal.style.display = 'none';
				document.body.style.overflow = '';
			}, 300);
		}
	},

	// ===========================================
	// DATABASE OPERATIONS
	// ===========================================
	saveItemToDB: async function(item) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vault_items'], 'readwrite');
			const store = transaction.objectStore('vault_items');

			const request = item.item_id ? store.put(item) : store.add(item);

			request.onsuccess = () => resolve(request.result);
			request.onerror = () => reject(request.error);
		});
	},

	getVaultItems: async function(vaultId) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vault_items'], 'readonly');
			const store = transaction.objectStore('vault_items');
			const index = store.index('vault_id');
			const request = index.getAll(vaultId);

			request.onsuccess = () => resolve(request.result || []);
			request.onerror = () => reject(request.error);
		});
	},

	saveVault: async function(vault) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vaults'], 'readwrite');
			const store = transaction.objectStore('vaults');
			const request = store.put(vault);

			request.onsuccess = () => resolve();
			request.onerror = () => reject(request.error);
		});
	},

	getAllVaults: async function() {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vaults'], 'readonly');
			const store = transaction.objectStore('vaults');
			const request = store.getAll();

			request.onsuccess = () => resolve(request.result || []);
			request.onerror = () => reject(request.error);
		});
	},

	deleteItemFromDB: async function(itemId) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vault_items'], 'readwrite');
			const store = transaction.objectStore('vault_items');
			const request = store.delete(itemId);

			request.onsuccess = () => resolve();
			request.onerror = () => reject(request.error);
		});
	},

	deleteVaultFromDB: async function(vaultId) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vaults'], 'readwrite');
			const store = transaction.objectStore('vaults');
			const request = store.delete(vaultId);

			request.onsuccess = () => resolve();
			request.onerror = () => reject(request.error);
		});
	},

	deleteAllVaultItems: async function(vaultId) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vault_items'], 'readwrite');
			const store = transaction.objectStore('vault_items');
			const index = store.index('vault_id');

			const getRequest = index.getAllKeys(vaultId);

			getRequest.onsuccess = () => {
				const keys = getRequest.result;
				if (keys.length === 0) {
					resolve();
					return;
				}

				let completed = 0;
				keys.forEach(key => {
					const deleteRequest = store.delete(key);
					deleteRequest.onsuccess = () => {
						completed++;
						if (completed === keys.length) {
							resolve();
						}
					};
					deleteRequest.onerror = () => reject(deleteRequest.error);
				});
			};

			getRequest.onerror = () => reject(getRequest.error);
		});
	},

	getVaultFromDB: async function(vaultId) {
		return new Promise((resolve, reject) => {
			if (!this.db) {
				reject(new Error('Database not initialized'));
				return;
			}

			const transaction = this.db.transaction(['vaults'], 'readonly');
			const store = transaction.objectStore('vaults');
			const request = store.get(vaultId);

			request.onsuccess = () => {
				if (request.result) {
					resolve(request.result);
				} else {
					reject(new Error('Vault not found'));
				}
			};
			request.onerror = () => reject(request.error);
		});
	},

	// ===========================================
	// EMERGENCY ACCESS
	// ===========================================
	showEmergencyModal: function() {
		this.showModal('emergencyModal');
	},

	// ===========================================
	// EMERGENCY KEY GENERATION (UPDATED FOR SV2.4 COMPATIBILITY)
	// ===========================================
	generateEmergencyKey: async function() {
		if (!this.currentVault || !this.cryptoBoundary?.encCryptoKey) {
			// Catatan: tetap izinkan proses jika vault terbuka; kalau encCryptoKey belum ada,
			// kita masih buat dan simpan format lama untuk backward compatibility.
			if (!this.currentVault) {
				this.showToast('Vault is locked. Please unlock first.', 'warning');
				return;
			}
		}

		try {
			// === OLD-BEHAVIOR: generate 32 random bytes and store as hex (preserve) ===
			const emergencyKeyBytes = crypto.getRandomValues(new Uint8Array(32));
			// Keep old storage format exactly as before
			localStorage.setItem('sv_emergency_key', this.uint8ArrayToHex(emergencyKeyBytes));

			// Optionally keep an encrypted copy (non-breaking, helpful for future)
			try {
				if (this.cryptoBoundary?.encCryptoKey) {
					const encrypted = await this.encryptData(emergencyKeyBytes, this.cryptoBoundary.encCryptoKey);
					// store encrypted ciphertext hex under a non-conflicting key (optional)
					localStorage.setItem('sv_emergency_key_enc', this.uint8ArrayToHex(new Uint8Array(encrypted.ciphertext)));
				}
			} catch (encErr) {
				// jangan ganggu flow utama jika enkripsi tidak tersedia / gagal
				console.warn('Failed to encrypt emergencyKeyBytes for storage:', encErr);
			}

			// === NEW: derive human-friendly printable key (12 chars) from the random bytes ===
			// Deterministic derivation from emergencyKeyBytes so printable key is bound to stored bytes.
			// Use SHA-256 of the random bytes and map bytes to A-Z0-9 characters.
			const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
			const digestBuffer = await crypto.subtle.digest('SHA-256', emergencyKeyBytes);
			const digest = new Uint8Array(digestBuffer);

			let shortKey = '';
			for (let i = 0; i < 12; i++) {
				// map each digest byte to chars (deterministic, uniform enough)
				shortKey += chars[digest[i] % chars.length];
			}
			const printableKey = `${shortKey.slice(0,4)}-${shortKey.slice(4,8)}-${shortKey.slice(8,12)}`;

			// === Store hash for new recovery flow (backward-compatible) ===
			const keyPlainNoDashes = shortKey; // normalized 12-char string
			const keyHash = await this.sha256Hex(keyPlainNoDashes);

			// store under both names so different modules find it
			localStorage.setItem('sv_v2_4_emergency_key_hash', keyHash);
			try {
				localStorage.setItem('emergency_key_hash', keyHash);
			} catch (e) {
				/* silent */ }

			// === UI: show result (kept style similar to new layout) ===
			const resultDiv = document.getElementById('emergencyResult');
			if (resultDiv) {
				resultDiv.style.display = 'block';
				resultDiv.innerHTML = `
                <div class="card compact warning">
                    <pre style="white-space: pre-wrap; font-family: monospace; font-size: 12px;">${printableKey}</pre>
                </div>
                <div class="input-hint caption mt-sm">
                    <i class="ph ph-warning"></i>
                    Store this key in a safe physical location!
                </div>
                <div class="mt-sm">
                    <button class="ios-button small full-width" onclick="downloadEmergencyKeyAsFile('${printableKey.replace(/'/g, "\\'")}')">
                        <i class="ph ph-download-simple"></i> Download as File
                    </button>
                </div>
            `;
			}

			setTimeout(() => {
				try {
					if (typeof downloadEmergencyKeyAsFile === 'function') {
						downloadEmergencyKeyAsFile(printableKey);
					} else {
						// Fallback jika fungsi belum tersedia
						console.warn('downloadEmergencyKeyAsFile not available yet');
					}
				} catch (e) {
					console.warn('Auto-download failed', e);
				}
			}, 500);

		} catch (error) {
			console.error('Emergency setup failed:', error);
			this.showToast('Error creating emergency access key.', 'danger');
		}
	},

	// ======================================
	// SERVICE WORKER UTILITIES
	// ======================================

	serviceWorker: {
		async getCacheInfo() {
			if ('serviceWorker' in navigator && 'caches' in window) {
				const cacheNames = await caches.keys();
				const info = {
					total: 0,
					caches: {}
				};

				for (const name of cacheNames) {
					const cache = await caches.open(name);
					const requests = await cache.keys();
					info.caches[name] = requests.length;
					info.total += requests.length;
				}

				return info;
			}
			return null;
		},

		async clearAllCaches() {
			if ('caches' in window) {
				const cacheNames = await caches.keys();
				await Promise.all(cacheNames.map(name => caches.delete(name)));
				return true;
			}
			return false;
		},

		async checkUpdate() {
			if ('serviceWorker' in navigator) {
				const registration = await navigator.serviceWorker.ready;
				const result = await registration.update();

				if (result) {
					this.showToast('Update downloaded. Reload to apply.', 'info');
					return true;
				}
			}
			return false;
		}
	},

	// ======================================
	// CACHE MANAGEMENT
	// ======================================

	showCacheManagement: function() {
		this.showModal('cacheModal');
		this.updateCacheInfo();
	},

	updateCacheInfo: async function() {
		const cacheInfo = await this.serviceWorker.getCacheInfo();
		const cacheSize = document.getElementById('cacheSize');
		const cacheUsageBar = document.getElementById('cacheUsageBar');

		if (cacheInfo && cacheSize && cacheUsageBar) {
			const total = cacheInfo.total;
			const usagePercent = Math.min(100, (total / 100) * 100);

			cacheSize.textContent = `${total} items`;
			cacheUsageBar.style.width = `${usagePercent}%`;
		} else {
			if (cacheSize) cacheSize.textContent = 'N/A';
			if (cacheUsageBar) cacheUsageBar.style.width = '0%';
		}
	},

	clearCache: async function() {
		if (await this.serviceWorker.clearAllCaches()) {
			this.showToast('Cache cleared successfully', 'success');
			this.updateCacheInfo();
		} else {
			this.showToast('Failed to clear cache', 'danger');
		}
	},

	updateApp: async function() {
		if (await this.serviceWorker.checkUpdate()) {
			this.showToast('Update available!', 'info');
		} else {
			this.showToast('App is up to date', 'info');
		}
	}
};

// ===========================================
// GLOBAL EXPORTS
// ===========================================

window.SafeVault = SafeVault;

window.attemptUnlock = () => SafeVault.attemptUnlock();
window.cancelCreateVault = function() {
	SafeVault.cancelCreateVault();
};
window.clearClipboardNow = () => SafeVault.clearClipboardNow();
window.clearSearch = () => SafeVault.clearSearch();
window.confirmDelete = () => SafeVault.confirmDelete();
window.confirmFactoryReset = () => SafeVault.confirmFactoryReset();
window.copyToClipboard = (text) => SafeVault.copyToClipboard(text);
window.createNewVault = () => SafeVault.createNewVault();
window.currentVaultForOptions = null;
window.deleteVault = () => SafeVault.deleteVault();
window.exportVault = () => SafeVault.showModal('exportModal');
window.finishOnboarding = () => SafeVault.finishOnboarding();
window.generateEmergencyKey = () => SafeVault.generateEmergencyKey();
window.hideModal = (id) => SafeVault.hideModal(id);
window.hideVaultSwitcher = () => SafeVault.hideVaultSwitcher();
window.importVault = () => SafeVault.showModal('importModal');
window.installPWA = () => installPWA();
window.keepClipboardData = () => SafeVault.keepClipboardData();
window.lockApp = () => SafeVault.lockApp();
window.nextOnboardingPage = () => SafeVault.nextOnboardingPage();
window.performExport = () => SafeVault.performExport();
window.previousOnboardingPage = () => SafeVault.previousOnboardingPage();
window.refreshItems = () => SafeVault.refreshItems();
window.renameVault = () => SafeVault.renameVault();
window.resetAutoLock = () => SafeVault.resetAutoLockTimer();
window.resetAutoLockTimer = () => SafeVault.resetAutoLockTimer();
window.saveItem = () => SafeVault.saveItem();
window.showCreateVaultScreen = () => SafeVault.showCreateVaultScreen();
window.showEmergencyModal = () => SafeVault.showEmergencyModal();
window.showModal = (id) => SafeVault.showModal(id);
window.showRecoveryModal = () => SafeVault.showRecoveryModal();
window.showSearch = () => SafeVault.showSearch();
window.showVaultOptions = (vaultId) => SafeVault.showVaultOptions(vaultId);
window.showVaultSwitcher = () => SafeVault.showVaultSwitcher();
window.switchVault = (vaultId) => SafeVault.switchVault(vaultId);
window.toggleSort = () => SafeVault.toggleSort();
window.togglePasswordVisibility = (inputId) => SafeVault.togglePasswordVisibility(inputId);
window.showCacheManagement = () => SafeVault.showCacheManagement();
window.clearCache = () => SafeVault.clearCache();
window.updateApp = () => SafeVault.updateApp();

// KHUSUS RECOVERY
window.showRecoveryModal = () => SafeVaultV2_4?.showModal();
window.hideRecoveryModal = () => SafeVaultV2_4?.hideModal();
window.toggleRecoveryHint = () => SafeVaultV2_4?.toggleHint();
window.tryRecovery = () => SafeVaultV2_4?.tryRecovery();
window.downloadRecoveryKey = () => SafeVaultV2_4?.downloadRecoveryKey();

// ===========================================
// EMERGENCY KEY DOWNLOAD HELPER
// ===========================================
window.downloadEmergencyKeyAsFile = function(key) {
	const content = `SAFEVAULT EMERGENCY RECOVERY KEY
==============================

KEY: ${key}

VAULT: ${SafeVault.currentVault?.name || 'Unknown'}
GENERATED: ${new Date().toISOString()}

IMPORTANT:
1. Store this file in a secure physical location
2. Do not share with anyone
3. Without this key, you cannot recover your vault if you forget the password

RECOVERY INSTRUCTIONS:
1. Click "Forgot Password?" on lock screen
2. Enter the key above (without dashes or with dashes)
3. Follow instructions to create new master password

WARNING:
This key is as sensitive as your vault password.`;

	const blob = new Blob([content], {
		type: 'text/plain'
	});
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = `safevault-emergency-key-${Date.now()}.txt`;
	document.body.appendChild(a);
	a.click();

	setTimeout(() => {
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}, 100);

	// Show confirmation
	if (SafeVault.showToast) {
		SafeVault.showToast('Emergency key downloaded successfully!', 'success');
	}
};

// ===========================================
// PWA INSTALL PROMPT
// ===========================================
let deferredPrompt;

window.addEventListener('beforeinstallprompt', (e) => {
	e.preventDefault();
	deferredPrompt = e;

	setTimeout(() => {
		if (deferredPrompt && !window.matchMedia('(display-mode: standalone)').matches) {
			showPWAInstallPrompt();
		}
	}, 30000);
});

function showPWAInstallPrompt() {
	const toast = document.createElement('div');
	toast.className = 'toast info';
	toast.innerHTML = `
        <div class="toast-content">
            <i class="ph ph-download-simple"></i>
            <div>
                <h3 class="mb-xs">Install SafeVault</h3>
                <p class="caption">Get full offline access and app experience</p>
            </div>
        </div>
        <button class="ios-button small" onclick="installPWA()">Install</button>
    `;
	document.getElementById('toastContainer').appendChild(toast);

	setTimeout(() => toast.classList.add('show'), 100);
	setTimeout(() => {
		toast.classList.remove('show');
		setTimeout(() => toast.remove(), 500);
	}, 10000);
}

function installPWA() {
	if (deferredPrompt) {
		deferredPrompt.prompt();
		deferredPrompt.userChoice.then((choiceResult) => {
			if (choiceResult.outcome === 'accepted') {
				SafeVault.showToast('SafeVault installed successfully!', 'success');
			}
			deferredPrompt = null;
		});
	}
}

// ===========================================
// SAFEVAULT v2.4 RECOVERY MODULE
// ===========================================
// Namespaced to avoid conflicts with existing code
window.SafeVaultV2_4 = (() => {
	const NS = 'sv_v2_4_';
	const MAX_ATTEMPTS = 3;
	const COOLDOWN_MINUTES = 30;

	// Storage helpers
	const ls = {
		get: (key) => localStorage.getItem(NS + key),
		set: (key, value) => localStorage.setItem(NS + key, value),
		remove: (key) => localStorage.removeItem(NS + key),
		getJSON: (key) => {
			const val = ls.get(key);
			return val ? JSON.parse(val) : null;
		},
		setJSON: (key, obj) => ls.set(key, JSON.stringify(obj))
	};

	// Auto-migrate old emergency key to new format on initialization
	async function migrateOldEmergencyKeyIfNeeded() {
		const oldKey = localStorage.getItem('sv_emergency_key');
		const newHash = ls.get('emergency_key_hash') || ls.get('sv_v2_4_emergency_key_hash');

		// If old key exists but no new hash, create the hash
		if (oldKey && !newHash) {
			try {
				console.log('Migrating old emergency key to new format...');

				// Convert hex to bytes
				const keyBytes = hexToUint8Array(oldKey);

				// Derive printable key (same algorithm as generateEmergencyKey)
				const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
				const digestBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
				const digest = new Uint8Array(digestBuffer);

				let shortKey = '';
				for (let i = 0; i < 12; i++) {
					shortKey += chars[digest[i] % chars.length];
				}

				// Store hash
				const keyHash = await sha256Hex(shortKey);
				ls.set('emergency_key_hash', keyHash);
				ls.set('sv_v2_4_emergency_key_hash', keyHash);

				console.log('Old emergency key migrated successfully');

			} catch (error) {
				console.error('Failed to migrate old emergency key:', error);
			}
		}
	}

	// Helper for hex conversion (since SafeVault might not be available)
	function hexToUint8Array(hex) {
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
		}
		return bytes;
	}

	// Web Crypto helper
	async function sha256Hex(input) {
		const encoder = new TextEncoder();
		const data = encoder.encode(input);
		const hash = await crypto.subtle.digest('SHA-256', data);
		const hashArray = Array.from(new Uint8Array(hash));
		return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
	}

	// Modal management
	function showModal() {
		const modal = document.getElementById('svRecoveryModal');
		if (!modal) return;

		modal.style.display = 'flex';
		setTimeout(() => {
			modal.classList.add('active');
			document.getElementById('svKeyInput')?.focus();
		}, 10);

		updateCooldownUI();
	}

	function hideModal() {
		const modal = document.getElementById('svRecoveryModal');
		if (!modal) return;

		modal.classList.remove('active');
		setTimeout(() => {
			modal.style.display = 'none';
			document.getElementById('svKeyInput').value = '';
		}, 300);
	}

	// Cooldown management
	function getCooldownRemaining() {
		const until = parseInt(ls.get('cooldown_until') || '0', 10);
		if (!until) return 0;
		return Math.max(0, until - Date.now());
	}

	function incrementAttempts() {
		const current = parseInt(ls.get('attempts') || '0', 10);
		const next = current + 1;
		ls.set('attempts', next.toString());

		if (next >= MAX_ATTEMPTS) {
			const until = Date.now() + COOLDOWN_MINUTES * 60 * 1000;
			ls.set('cooldown_until', until.toString());
		}
	}

	function resetAttempts() {
		ls.remove('attempts');
		ls.remove('cooldown_until');
	}

	function updateCooldownUI() {
		const remaining = getCooldownRemaining();
		const notice = document.getElementById('svCooldownNotice');
		const text = document.getElementById('svCooldownText');
		const input = document.getElementById('svKeyInput');
		const tryBtn = document.querySelector('#svRecoveryModal .ios-button.primary');

		if (remaining > 0) {
			if (notice) notice.style.display = 'block';
			if (text) {
				const minutes = Math.ceil(remaining / (60 * 1000));
				text.textContent = `Tunggu ${minutes} menit sebelum mencoba lagi`;
			}
			if (input) input.disabled = true;
			if (tryBtn) tryBtn.disabled = true;

			// Update every minute
			setTimeout(updateCooldownUI, 60000);
		} else {
			if (notice) notice.style.display = 'none';
			if (input) input.disabled = false;
			if (tryBtn) tryBtn.disabled = false;
		}
	}

	// Hint management
	async function toggleHint() {
		const hintText = document.getElementById('svHintText');
		const hintBtn = document.getElementById('svBtnShowHint');

		if (!hintText || !hintBtn) return;

		if (hintText.classList.contains('hidden')) {
			// Try to get hint from current vault
			let hint = 'Tidak ada hint tersimpan untuk vault ini';

			try {
				// Check if there's a hint in current vault
				const vaults = await SafeVault.getAllVaults?.();
				const currentVault = vaults?.find(v => v.vault_id === SafeVault.currentVaultId);

				if (currentVault?.password_hint_encrypted && SafeVault.cryptoBoundary?.encCryptoKey) {
					// Decrypt hint
					const encryptedHint = SafeVault.base64ToUint8Array(currentVault.password_hint_encrypted);
					const iv = encryptedHint.slice(0, SafeVault.CRYPTO.IV_LENGTH);
					const ciphertext = encryptedHint.slice(SafeVault.CRYPTO.IV_LENGTH).buffer;

					const decryptedBytes = await SafeVault.decryptData(
						iv,
						ciphertext,
						SafeVault.cryptoBoundary.encCryptoKey
					);

					hint = new TextDecoder().decode(decryptedBytes);
				}
			} catch (error) {
				console.warn('Failed to decrypt hint:', error);
				hint = 'Tidak dapat memuat hint';
			}

			hintText.textContent = hint;
			hintText.classList.remove('hidden');
			hintBtn.textContent = 'Sembunyikan';
		} else {
			hintText.classList.add('hidden');
			hintBtn.textContent = 'Lihat';
		}
	}

	// Recovery key validation
	async function tryRecovery() {
		// Check cooldown
		if (getCooldownRemaining() > 0) {
			SafeVault.showToast?.('Tunggu sebelum mencoba lagi', 'warning');
			return;
		}

		const input = document.getElementById('svKeyInput');
		if (!input) return;

		let key = input.value.trim().toUpperCase();

		// Normalize input: remove dashes and spaces
		key = key.replace(/[-\s]/g, '');

		// Check length to determine format
		if (key.length === 64) {
			// Old 32-byte hex format - check if it matches stored sv_emergency_key
			const storedOldKey = localStorage.getItem('sv_emergency_key');
			if (storedOldKey && storedOldKey.toUpperCase() === key) {
				// Old format matches - convert to new format deterministically
				try {
					const keyBytes = SafeVault.hexToUint8Array(key);
					const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
					const digestBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
					const digest = new Uint8Array(digestBuffer);

					let shortKey = '';
					for (let i = 0; i < 12; i++) {
						shortKey += chars[digest[i] % chars.length];
					}

					// Now check the hash
					const keyHash = await sha256Hex(shortKey);
					const storedHash = ls.get('emergency_key_hash') || ls.get('sv_v2_4_emergency_key_hash');

					if (storedHash && keyHash === storedHash) {
						// Success with old format
						resetAttempts();
						const event = new CustomEvent('sv:recovery:success', {
							detail: {
								timestamp: Date.now()
							}
						});
						window.dispatchEvent(event);
						SafeVault.showToast?.('Recovery berhasil dengan emergency key lama!', 'success');
						await performMasterReset();
						return;
					}
				} catch (error) {
					console.error('Old format conversion failed:', error);
				}
			}

			// If we get here, old format failed
			incrementAttempts();
			updateCooldownUI();
			SafeVault.showToast?.('Emergency key lama tidak valid', 'danger');
			return;

		} else if (key.length === 12) {
			// New format - check hash
			const storedHash = ls.get('emergency_key_hash') || ls.get('sv_v2_4_emergency_key_hash');

			if (!storedHash) {
				SafeVault.showToast?.('Tidak ada recovery key tersimpan di perangkat ini', 'warning');
				return;
			}

			const inputHash = await sha256Hex(key);

			if (inputHash === storedHash) {
				// Success
				resetAttempts();
				const event = new CustomEvent('sv:recovery:success', {
					detail: {
						timestamp: Date.now()
					}
				});
				window.dispatchEvent(event);
				SafeVault.showToast?.('Recovery berhasil!', 'success');
				await performMasterReset();
			} else {
				incrementAttempts();
				updateCooldownUI();

				const attempts = parseInt(ls.get('attempts') || '0', 10);
				const remaining = MAX_ATTEMPTS - attempts;

				if (remaining > 0) {
					SafeVault.showToast?.(`Recovery key salah. ${remaining} percobaan tersisa`, 'danger');
				} else {
					SafeVault.showToast?.(`Terlalu banyak percobaan. Tunggu ${COOLDOWN_MINUTES} menit`, 'danger');
				}
			}
		} else {
			// Invalid format
			SafeVault.showToast?.(
				'Format key tidak valid. Gunakan:\n' +
				'- Format baru: XXXX-XXXX-XXXX (12 karakter)\n' +
				'- Format lama: 64 karakter hex (32 byte)',
				'warning'
			);
			incrementAttempts();
			updateCooldownUI();
		}
	}

	// Generate and download recovery key
	async function downloadRecoveryKey() {
		// Generate random key
		const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		let key = '';

		for (let i = 0; i < 12; i++) {
			key += chars[Math.floor(Math.random() * chars.length)];
		}

		// Format as XXXX-XXXX-XXXX
		const formattedKey = `${key.slice(0, 4)}-${key.slice(4, 8)}-${key.slice(8, 12)}`;

		// Store hash (not the plain key)
		const keyHash = await sha256Hex(key);
		ls.set('emergency_key_hash', keyHash);

		// Also store timestamp
		ls.set('key_generated_at', Date.now().toString());

		// Create download
		const content = `SAFEVAULT RECOVERY KEY
========================

KEY: ${formattedKey}

VAULT ID: ${SafeVault.currentVaultId || 'Unknown'}
GENERATED: ${new Date().toISOString()}

PENTING:
1. Simpan file ini di tempat yang aman
2. Jangan bagikan dengan siapapun
3. Tanpa key ini, data tidak dapat dipulihkan jika lupa password
4. Key hanya berlaku untuk vault ini

INSTRUKSI PEMULIHAN:
1. Klik "Lupa Password?" di layar kunci
2. Masukkan key di atas
3. Ikuti instruksi untuk membuat password baru

PERINGATAN:
Key ini sama sensitifnya dengan password vault Anda.`;

		const blob = new Blob([content], {
			type: 'text/plain'
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `safevault-recovery-key-${Date.now()}.txt`;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);

		SafeVault.showToast?.('Recovery key berhasil diunduh. Simpan di tempat aman!', 'success');

		// Ask for confirmation
		setTimeout(() => {
			const confirmed = confirm(
				'PENTING: Pastikan Anda telah menyimpan recovery key!\n\n' +
				'Key telah diunduh. Apakah Anda telah menyimpannya di tempat yang aman?'
			);

			if (confirmed) {
				ls.set('key_confirmed_at', Date.now().toString());
				SafeVault.showToast?.('Terima kasih telah mengonfirmasi penyimpanan key', 'info');
			}
		}, 1000);
	}

	// Initialize recovery module
	async function init() {
		await migrateOldEmergencyKeyIfNeeded();
		console.log('SafeVaultV2_4 Recovery Module initialized');

		// Auto-format input
		const keyInput = document.getElementById('svKeyInput');
		if (keyInput) {
			keyInput.addEventListener('input', function(e) {
				let value = e.target.value.replace(/[^A-Z0-9]/g, '').toUpperCase();
				if (value.length > 12) value = value.slice(0, 12);

				if (value.length > 4) value = value.slice(0, 4) + '-' + value.slice(4);
				if (value.length > 9) value = value.slice(0, 9) + '-' + value.slice(9);

				e.target.value = value;
			});
		}

		// Enter key to submit
		if (keyInput) {
			keyInput.addEventListener('keypress', function(e) {
				if (e.key === 'Enter') {
					tryRecovery();
				}
			});
		}

		// Initialize cooldown UI
		updateCooldownUI();
	}

	// Public API
	return {
		showModal,
		hideModal,
		toggleHint,
		tryRecovery,
		downloadRecoveryKey,
		init,
		// For testing/debugging
		_internal: {
			ls,
			sha256Hex,
			getCooldownRemaining,
			resetAttempts
		}
	};
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', () => {
		SafeVaultV2_4.init();
	});
} else {
	SafeVaultV2_4.init();
}

// confirmFactoryReset or redirect to new flow
window.confirmFactoryReset = () => {
	if (confirm('PERINGATAN: Tindakan ini akan menghapus semua data vault di browser ini.\n\nApakah Anda yakin ingin melakukan reset pabrik?')) {
		// Clear recovery module data too
		Object.keys(localStorage)
			.filter(key => key.startsWith('sv_v2_4_'))
			.forEach(key => localStorage.removeItem(key));

		// Then trigger the existing factory reset logic
		SafeVault.confirmFactoryReset?.();
	}
};

// ===========================================
// INITIALIZATION
// ===========================================
document.addEventListener('DOMContentLoaded', () => {
	const searchContainer = document.getElementById('searchContainer');

	// Klik DI DALAM search → jangan nutup
	searchContainer?.addEventListener('click', e => e.stopPropagation());

	// Klik DI LUAR search → tutup
	document.addEventListener('click', () => {
		if (searchContainer) {
			searchContainer.style.display = 'none';
		}
	});

	console.log('[SAFEVAULT] DOM ready, starting initialization...');

	const loading = document.getElementById('initialLoadScreen');
	if (loading) {
		loading.style.display = 'flex';
		loading.style.opacity = '1';
		loading.style.visibility = 'visible';
	}

	setTimeout(() => {
		SafeVault.init().catch(error => {
			console.error('SafeVault initialization failed:', error);
			SafeVault.handleInitError(error);
		});
	}, 50);
});

// Fallback initialization
if (document.readyState !== 'loading') {
	setTimeout(() => {
		SafeVault.init().catch(error => {
			console.error('SafeVault initialization failed:', error);
			SafeVault.handleInitError(error);
		});
	}, 100);
}

// Service Worker Registration
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/safevault/script/sw.js')
        .then(() => console.log('SW registered'))
        .catch(console.error);
    
    window.SafeVault = window.SafeVault || {};
    
    SafeVault.serviceWorker = {
        async clearAllCaches() {
            if (!navigator.serviceWorker?.controller) return false;
            navigator.serviceWorker.controller.postMessage({ type: 'CLEAR_CACHE' });
            return true;
        },
        
        async checkUpdate() {
            if (!navigator.serviceWorker) return false;
            const reg = await navigator.serviceWorker.getRegistration();
            if (reg) await reg.update();
            return true;
        }
    };
}
