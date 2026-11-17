/* 星星工作台 - 离线缓存 Service Worker */
const CACHE = 'xingxing-workbench-lite-v16';
/* SW 脚本 URL 带 sharecode（注册时附加），取出来给所有同源请求补上——
   发布网关对每个请求的 URL 都校验 sharecode，缺了会 403「链接不完整」 */
const SC = new URLSearchParams(self.location.search).get('sharecode') || '';
const withSC = (u) => SC ? (u + (u.includes('?') ? '&' : '?') + 'sharecode=' + encodeURIComponent(SC)) : u;
const ASSETS = ['./', './index.html', './apple-touch-icon.png', './manifest.json'].map(withSC);

// 安装：预缓存核心资源
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

// 激活：清理旧缓存
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// 请求：网络优先，失败回退缓存（在线时永远拿到最新版，离线时用缓存）
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  if (SC && !url.searchParams.has('sharecode') && !url.pathname.startsWith('/.cloud/')) {
    url.searchParams.set('sharecode', SC);
    e.respondWith(
      fetch(new Request(url, e.request))
        .then((res) => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE).then((c) => c.put(url.toString(), clone));
          }
          return res;
        })
        .catch(() => caches.match(url.toString()).then((m) => m || caches.match(e.request)))
    );
    return;
  }
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
