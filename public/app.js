'use strict';

// ---------- State ----------
const state = {
  me: null,
  currentView: 'feed', // feed | search | jobs | profile | messages
  profileUserId: null,
  jobsTab: 'browse', // browse | my-apps | my-jobs
  pendingAction: null,
  notifications: [],
  notificationsUnread: 0,
  notifPollTimer: null,
};

// ---------- Helpers ----------
const $ = (sel) => document.querySelector(sel);
const app = $('#app');
const TYPE_META = {
  general: { label: 'General', emoji: '📝' },
  offer: { label: 'Offer', emoji: '🏷️' },
  advertisement: { label: 'Advertisement', emoji: '📢' },
};

const ICONS = {
  heart: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8z"></path></svg>',
  heartFilled: '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8z"></path></svg>',
  comment: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.7z"></path></svg>',
};

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Something went wrong.');
  return data;
}

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60); if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60); if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24); if (d < 7) return `${d}d`;
  return new Date(iso).toLocaleDateString();
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

const AVATAR_GRADS = [
  'linear-gradient(135deg,#4ADE80,#22D3EE)',
  'linear-gradient(135deg,#F59E0B,#F472B6)',
  'linear-gradient(135deg,#60A5FA,#8C79FF)',
  'linear-gradient(135deg,#F472B6,#C084FC)',
  'linear-gradient(135deg,#34D399,#F59E0B)',
  'linear-gradient(135deg,#C084FC,#60A5FA)',
];

function gradFor(name) {
  let h = 0;
  const s = String(name || '');
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return AVATAR_GRADS[h % AVATAR_GRADS.length];
}

function shortName(name) {
  const s = String(name || '');
  return s.length > 14 ? s.slice(0, 13) + '…' : s;
}

function categoryColor(cat) {
  const c = String(cat || '').toLowerCase();
  if (/garden|food|kitchen|bever|barista|cook/i.test(c)) return '#4ADE80';
  if (/delivery|logist|warehouse|rider|transport/i.test(c)) return '#F59E0B';
  if (/design|ui|tech|technology|engineer|develop|intern/i.test(c)) return '#60A5FA';
  if (/marketing|social|sales|retail|manage/i.test(c)) return '#F472B6';
  if (/writ|photo|creativ|editor/i.test(c)) return '#C084FC';
  return '#60A5FA';
}

function initials(name) {
  return (name || '?').split(/\s+/).slice(0, 2).map((p) => p[0]).join('').toUpperCase();
}

function avatar(user, size = 40) {
  const inner = user.photo
    ? `<img src="${user.photo}" alt="" />`
    : initials(user.name);
  return `<span class="ring" style="width:${size}px;height:${size}px;flex:0 0 ${size}px"><span class="avatar-circle" style="font-size:${Math.round(size * 0.38)}px;background:${gradFor(user.name)}">${inner}</span></span>`;
}

function toast(msg) {
  const t = $('#toast');
  const txt = $('#toast-text');
  if (txt) txt.textContent = msg;
  else t.textContent = msg;
  t.classList.remove('hidden');
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.classList.add('hidden'); t.classList.remove('show'); }, 2600);
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function showLightbox(src) {
  const ov = document.createElement('div');
  ov.className = 'overlay';
  ov.style.cssText = 'z-index:400;background:rgba(0,0,0,0.9)';
  ov.innerHTML = `<img src="${src}" style="max-width:92vw;max-height:92vh;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.6)" />`;
  ov.addEventListener('click', () => ov.remove());
  document.body.appendChild(ov);
}

function setActiveNav(view) {
  document.querySelectorAll('.main-nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === view));
}

// ---------- Auth ----------
const authZone = $('#auth-zone');

function renderAuth() {
  if (state.me) {
    authZone.innerHTML = `
      <div class="notif-wrap">
        <button class="icon-btn" id="notif-btn" title="Notifications" aria-label="Notifications">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.7 21a2 2 0 0 1-3.4 0"></path></svg>
          <span class="badge hidden" id="notif-badge">0</span>
        </button>
        <div class="notif-panel" id="notif-panel"></div>
      </div>
      <div class="me-wrap">
        <a href="#" class="avatar-mini" id="nav-profile" title="Account">
          ${avatar(state.me, 34)} <span class="name-sm">${escapeHtml(state.me.name.split(' ')[0])}</span>
        </a>
        <div class="me-panel" id="me-panel">
          <a href="#" id="me-profile-link"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> My profile</a>
          <a href="#" id="me-jobs-link"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg> My posted jobs</a>
          <button class="logout" id="logout-btn">Log out</button>
        </div>
      </div>
    `;
    $('#nav-profile').addEventListener('click', (e) => { e.preventDefault(); toggleMePanel(); });
    $('#me-profile-link').addEventListener('click', (e) => { e.preventDefault(); closePanels(); goProfile(state.me.id); });
    $('#me-jobs-link').addEventListener('click', (e) => { e.preventDefault(); closePanels(); goJobs('my-jobs'); });
    $('#logout-btn').addEventListener('click', async () => {
      await fetch('/api/logout', { method: 'POST' });
      state.me = null;
      stopNotifPoll();
      closePanels();
      renderAuth();
      goFeed();
      toast('Signed out.');
    });
    $('#notif-btn').addEventListener('click', (e) => { e.stopPropagation(); toggleNotifPanel(); });
    loadNotifications();
  } else {
    stopNotifPoll();
    authZone.innerHTML = `
      <button class="btn btn-ghost" id="login-btn">Log in</button>
      <button class="btn btn-primary" id="signup-btn">Sign up</button>
    `;
    $('#login-btn').addEventListener('click', () => openAuth('login'));
    $('#signup-btn').addEventListener('click', () => openAuth('signup'));
  }
}

function closePanels() {
  const np = $('#notif-panel');
  if (np) np.classList.remove('open');
  const mp = $('#me-panel');
  if (mp) mp.classList.remove('open');
}

function toggleMePanel() {
  const mp = $('#me-panel');
  const np = $('#notif-panel');
  if (np) np.classList.remove('open');
  if (mp) mp.classList.toggle('open');
}

async function toggleNotifPanel() {
  const np = $('#notif-panel');
  const mp = $('#me-panel');
  if (mp) mp.classList.remove('open');
  if (!np) return;
  np.classList.toggle('open');
  if (np.classList.contains('open')) {
    np.innerHTML = '<div class="notif-empty">Loading…</div>';
    loadNotifications().then(() => renderNotifPanel());
  }
}

async function renderNotifPanel() {
  const np = $('#notif-panel');
  if (!np) return;
  np.innerHTML = '';
  if (!state.notifications.length) {
    np.innerHTML = '<div class="notif-empty">You\'re all caught up 🎉</div>';
  } else {
    state.notifications.forEach((n) => {
      const el = document.createElement('div');
      el.className = 'notif-item';
      el.dataset.notifLink = n.link || '';
      el.innerHTML = `
        <div class="notif-dot" style="${n.read ? 'background:var(--surface-3)' : ''}"></div>
        <div class="notif-text">${avatar(n.actor, 30)}<div style="margin-top:4px">${escapeHtml(n.text)}</div><div class="notif-time">${timeAgo(n.createdAt)}</div></div>
      `;
      el.addEventListener('click', () => {
        closePanels();
        const link = el.dataset.notifLink;
        if (link === '/feed') goFeed();
        else if (link === '/jobs') goJobs('browse');
        else if (link === '/messages') goMessages();
      });
      np.appendChild(el);
    });
  }
  if (state.notificationsUnread > 0) {
    api('/api/notifications/read', { method: 'POST' }).then(() => {
      state.notificationsUnread = 0;
      updateNotifBadge();
    }).catch(() => {});
  }
}

// ---------- Auth modal ----------
let authMode = 'login';
const authOverlay = $('#auth-overlay');

function openAuth(mode = 'login') {
  authMode = mode;
  $('#auth-title').textContent = mode === 'login' ? 'Welcome back' : 'Create your account';
  $('#auth-sub').textContent = mode === 'login' ? 'Log in to continue.' : 'Sign up to post, like, comment and apply for jobs.';
  $('#auth-submit').textContent = mode === 'login' ? 'Log in' : 'Sign up';
  $('#auth-name').classList.toggle('hidden', mode !== 'signup');
  $('#auth-skills').classList.toggle('hidden', mode !== 'signup');
  $('#auth-password').setAttribute('autocomplete', mode === 'login' ? 'current-password' : 'new-password');
  $('#auth-switch-text').textContent = mode === 'login' ? "Don't have an account?" : 'Already have an account?';
  $('#auth-switch').textContent = mode === 'login' ? 'Sign up' : 'Log in';
  $('#auth-error').classList.add('hidden');
  authOverlay.classList.remove('hidden');
  $('#auth-email').value = '';
  $('#auth-password').value = '';
  $('#auth-name').value = '';
  $('#auth-skills').value = '';
  setTimeout(() => $('#auth-email').focus(), 50);
}

function closeAuth() { authOverlay.classList.add('hidden'); }

$('#auth-close').addEventListener('click', closeAuth);
$('#auth-overlay').addEventListener('click', (e) => { if (e.target === authOverlay) closeAuth(); });
$('#auth-switch').addEventListener('click', (e) => {
  e.preventDefault();
  openAuth(authMode === 'login' ? 'signup' : 'login');
});

$('#auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#auth-error');
  err.classList.add('hidden');
  const submitBtn = $('#auth-submit');
  submitBtn.disabled = true;

  try {
    const body = {};
    if (authMode === 'signup') {
      body.name = $('#auth-name').value.trim();
      if (!body.name) throw new Error('Please enter a name.');
      body.skills = $('#auth-skills').value.split(',').map((s) => s.trim()).filter(Boolean);
    }
    body.email = $('#auth-email').value.trim();
    body.password = $('#auth-password').value;

    const data = await api('/api/' + authMode, { method: 'POST', body: JSON.stringify(body) });
    state.me = data.user;
    closeAuth();
    renderAuth();
    if (state.pendingAction) {
      const action = state.pendingAction;
      state.pendingAction = null;
      await runAction(action);
    } else {
      refreshView();
    }
    toast(authMode === 'login' ? 'Welcome back!' : 'Account created — welcome!');
  } catch (error) {
    err.textContent = error.message;
    err.classList.remove('hidden');
  } finally {
    submitBtn.disabled = false;
  }
});

// ---------- Gotcha modal ----------
const gotchaOverlay = $('#gotcha-overlay');
function showGotcha(text) {
  $('#gotcha-text').textContent = text;
  $('#gotcha-title').textContent = state.me ? 'Sign in again' : 'One more step';
  $('#gotcha-signup').textContent = state.me ? 'Log in' : 'Sign up';
  gotchaOverlay.classList.remove('hidden');
}
function closeGotcha() { gotchaOverlay.classList.add('hidden'); }

$('#gotcha-cancel').addEventListener('click', closeGotcha);
$('#gotcha-signup').addEventListener('click', () => {
  closeGotcha();
  openAuth(state.me ? 'login' : 'signup');
});
$('#gotcha-overlay').addEventListener('click', (e) => { if (e.target === gotchaOverlay) closeGotcha(); });

// ---------- Sheet modal (composer, apply, applicants, job post) ----------
const sheetOverlay = $('#sheet-overlay');
function openSheet(html) {
  $('#sheet-body').innerHTML = html;
  sheetOverlay.classList.remove('hidden');
}
function closeSheet() {
  sheetOverlay.classList.add('hidden');
  $('#sheet-body').innerHTML = '';
}
sheetOverlay.addEventListener('click', (e) => { if (e.target === sheetOverlay) closeSheet(); });

// ---------- Actions ----------
async function runAction(action) {
  if (action.type === 'like') await doLike(action.postId);
  if (action.type === 'comment') await doComment(action.postId, action.text);
  if (action.type === 'post') await doCreatePost(action.text, action.image);
  if (action.type === 'apply') await doApply(action.jobId);
}

async function requireLogin(action, guestText) {
  if (state.me) await runAction(action);
  else { state.pendingAction = action; showGotcha(guestText); }
}

// =====================================================================
// HOME FEED
// =====================================================================
async function loadFeed() {
  state.currentView = 'feed';
  setActiveNav('feed');
  document.body.classList.remove('narrow');
  app.innerHTML = '<div class="spinner">Loading feed...</div>';
  try {
    const [postsData, jobsData] = await Promise.all([
      api('/api/posts'),
      api('/api/jobs'),
    ]);
    renderFeed(postsData.posts, jobsData.jobs);
  } catch (e) {
    app.innerHTML = `<div class="empty">${e.message}</div>`;
  }
}

function renderFeed(posts, jobs) {
  renderLeftSidebar(posts, jobs);
  renderRightSidebar(posts, jobs);

  const fab = state.me
    ? `<button class="fab" id="fab-new-post" title="New post">＋</button>`
    : '';
  const jobCards = jobs.filter((j) => !j.filled).map(feedJobCard).join('');
  const postCards = posts.length
    ? posts.map(postHtml).join('')
    : '';
  const list = [jobCards, postCards].filter(Boolean).join('') || '<div class="empty">Nothing here yet. Be the first to share something!</div>';

  app.innerHTML = fab + storiesHtml(posts, jobs) + list;
  const fabBtn = $('#fab-new-post');
  if (fabBtn) fabBtn.addEventListener('click', showComposer);
  bindFeed();
  bindJobCards(document);
  document.querySelectorAll('.story[data-goprofile]').forEach((el) => {
    el.addEventListener('click', () => goProfile(Number(el.dataset.goprofile)));
  });
  document.querySelectorAll('[data-skip]').forEach((el) => {
    el.addEventListener('click', () => {
      const c = el.closest('[data-job]') || el.closest('.card');
      if (c) c.remove();
    });
  });
  bindSidebars();
}

function storiesHtml(posts, jobs) {
  const map = new Map();
  posts.forEach((p) => {
    if (p.author) map.set(p.author.id, { id: p.author.id, name: p.author.name, photo: p.author.photo, hiring: p.author.role === 'owner' });
  });
  jobs.forEach((j) => {
    if (j.giver) map.set(j.giver.id, { id: j.giver.id, name: j.giver.name, photo: j.giver.photo, hiring: true });
  });
  const items = [];
  if (state.me) {
    items.push(`
      <div class="story" data-goprofile="${state.me.id}">
        <div class="ring gray"><div class="avatar-circle" style="background:var(--surface-2);border-style:dashed;color:var(--text-soft)">+</div></div>
        <div class="story-label">Your story</div>
      </div>`);
  }
  [...map.values()].slice(0, 6).forEach((u) => {
    items.push(`
      <div class="story" data-goprofile="${u.id}">
        ${avatar(u, 60)}
        <div class="story-label">${escapeHtml(shortName(u.name))}</div>
        <div class="story-sub ${u.hiring ? '' : 'blue'}">${u.hiring ? 'Hiring now' : 'Open to work'}</div>
      </div>`);
  });
  return `<div class="stories">${items.join('')}</div>`;
}

function feedJobCard(j) {
  const catColor = categoryColor(j.category);
  const mySkills = state.me && state.me.skills ? state.me.skills : [];
  const match = mySkills.some((s) => {
    const lo = s.toLowerCase();
    return (j.category && j.category.toLowerCase().includes(lo)) || j.title.toLowerCase().includes(lo);
  });
  return `
    <div class="card job-card feed-stagger" data-job="${j.id}">
      <div class="cat-bar" style="background:${catColor}"></div>
      <div class="card-head">
        ${avatar(j.giver, 40)}
        <div class="head-meta">
          <div class="who"><a href="#" class="post-author" data-user="${j.giver.id}">${escapeHtml(j.giver.name)}</a> <span class="hiring-tag">Hiring</span></div>
          <div class="meta-line">${escapeHtml(j.locationText || 'Local')} · ${timeAgo(j.createdAt)}</div>
        </div>
        <button class="more-btn"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg></button>
      </div>
      <div class="job-body">
        <div class="job-title">${escapeHtml(j.title)}</div>
        <p class="job-desc">${escapeHtml(j.description || '')}</p>
        <div class="job-tags">
          ${j.wage ? `<span class="wage-pill">${escapeHtml(j.wage)}</span>` : ''}
          ${j.category ? `<span class="tag ${match ? 'match' : ''}">${escapeHtml(j.category)}</span>` : ''}
          ${match ? '<span class="tag match">Matches your skills</span>' : ''}
        </div>
        <div class="job-facts">
          <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> ${escapeHtml(j.locationText || 'Local')}</span>
          <span>👥 ${j.applicantCount} applied</span>
        </div>
      </div>
      <div class="card-actions">
        <div class="left-actions"></div>
        <div class="apply-group">
          ${state.me && j.giver.id === state.me.id
            ? '<button class="btn-apply applied" disabled>Your job</button>'
            : j.myStatus
              ? `<button class="btn-apply applied" disabled>${j.myStatus === 'accepted' ? 'Accepted <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>' : 'Applied <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>'}</button>`
              : `<button class="btn-skip" data-skip="${j.id}">Skip</button>
                 <button class="btn-apply" data-apply="${j.id}">Apply</button>`}
        </div>
      </div>
    </div>
  `;
}

function postHtml(p) {
  const tag = TYPE_META[p.type] || TYPE_META.general;
  const isOwn = state.me && state.me.id === p.author.id;
  const hiring = p.author.role === 'owner';
  return `
    <div class="card post feed-stagger" data-post="${p.id}">
      <div class="card-head">
        ${avatar(p.author, 40)}
        <div class="head-meta">
          <div class="who"><a href="#" class="post-author" data-user="${p.author.id}">${escapeHtml(p.author.name)}</a> ${hiring ? '<span class="hiring-tag">Hiring</span>' : ''}</div>
          <div class="meta-line"><span class="post-tag ${p.type}">${tag.label}</span> · ${timeAgo(p.createdAt)}</div>
        </div>
        <button class="more-btn"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg></button>
      </div>
      ${p.body ? `<div class="post-caption">${escapeHtml(p.body)}</div>` : ''}
      ${p.image ? `<img src="${p.image}" class="post-img" data-lightbox="${p.image}" alt="" />` : ''}
      <div class="card-actions">
        <div class="left-actions">
          <button class="act-btn ${p.likedByMe ? 'liked' : ''}" id="like-${p.id}">
            <span class="btn-ico">${p.likedByMe ? ICONS.heartFilled : ICONS.heart}</span>
            <span id="like-count-${p.id}">${p.likeCount}</span>
          </button>
          <button class="act-btn" id="comment-btn-${p.id}"><span class="btn-ico">${ICONS.comment}</span><span id="comment-count-${p.id}">${p.commentCount}</span></button>
        </div>
        ${isOwn ? `
          <div class="apply-group">
            <button class="btn-skip" data-edit-post="${p.id}">Edit</button>
            <button class="btn-skip" data-delete-post="${p.id}" style="color:var(--danger)">Delete</button>
          </div>` : ''}
      </div>
      <div class="comments hidden" id="comments-${p.id}"></div>
      <div class="comment-form">
        ${state.me ? `
          <span class="ring" style="width:32px;height:32px;flex:0 0 32px"><span class="avatar-circle" style="font-size:13px;background:${gradFor(state.me.name)}">${initials(state.me.name)}</span></span>
          <input type="text" id="comment-input-${p.id}" placeholder="Write a comment..." />`
          : `<button class="btn btn-primary btn-block" id="comment-login-${p.id}">Log in to comment</button>`}
      </div>
    </div>
  `;
}

function renderLeftSidebar(posts, jobs) {
  const left = $('#col-left');
  if (!left) return;
  let html;
  if (state.me) {
    const mine = posts.filter((p) => p.author.id === state.me.id);
    const postCount = mine.length;
    const likeCount = mine.reduce((s, p) => s + p.likeCount, 0);
    const score = postCount + likeCount;
    html = `
      <div class="mini-profile">
        <div style="display:inline-block">${avatar(state.me, 52)}</div>
        <h3>${escapeHtml(state.me.name)}</h3>
        <p>${escapeHtml(state.me.skills.slice(0, 2).join(' · ') || 'Member of Announce')}</p>
        <div class="mini-stats">
          <div>${postCount}<span>Posts</span></div>
          <div>${likeCount}<span>Likes</span></div>
          <div>${score}<span>Score</span></div>
        </div>
      </div>`;
  } else {
    html = `
      <div class="mini-profile">
        <div style="display:inline-block"><span class="ring"><span class="avatar-circle" style="font-size:20px;width:52px;height:52px;background:linear-gradient(135deg,#6C7BFF,#8C79FF)">A</span></span></div>
        <h3>Welcome</h3>
        <p>Join Announce to post, apply and chat.</p>
        <div style="display:flex;gap:8px;margin-top:12px">
          <button class="btn btn-ghost btn-sm" style="flex:1" id="side-login">Log in</button>
          <button class="btn btn-primary btn-sm" style="flex:1" id="side-signup">Sign up</button>
        </div>
      </div>`;
  }
  left.innerHTML = html;
}

function renderRightSidebar(posts, jobs) {
  const right = $('#col-right');
  if (!right) return;
  let html = '';
  if (state.me) {
    let strength = 30;
    if (state.me.skills.length) strength += 25;
    if (state.me.bio) strength += 25;
    if (state.me.photo) strength += 20;
    strength = Math.min(100, strength);
    html += `
      <div class="side-card">
        <h4>Profile strength</h4>
        <div class="progress-track"><div class="progress-fill" style="width:${strength}%"></div></div>
        <div class="progress-label"><b>${strength}% complete</b>${strength < 100 ? ' — add skills, bio or a photo for more matches' : ' — you look great!'}</div>
        <a class="side-cta" href="#" id="side-complete-profile">${strength < 100 ? 'Complete profile' : 'View profile'}</a>
      </div>`;
  } else {
    html += `
      <div class="side-card">
        <h4>Looking for work?</h4>
        <div class="progress-track"><div class="progress-fill" style="width:100%"></div></div>
        <div class="progress-label"><b>Create an account</b> to apply in one tap.</div>
        <a class="side-cta" href="#" id="side-signup-cta">Sign up free</a>
      </div>`;
  }

  const open = jobs.filter((j) => !j.filled).slice(0, 3);
  if (open.length) {
    html += `
      <div class="side-card">
        <h4>Jobs near you <span class="count">${open.length} open</span></h4>
        ${open.map((j) => `
          <div class="mini-job" data-minijob="${j.id}">
            <div class="mini-job-dot" style="background:${categoryColor(j.category)}"></div>
            <div class="mini-job-info">
              <div class="t">${escapeHtml(j.title)}</div>
              <div class="s">${escapeHtml(j.locationText || 'Local')}${j.wage ? ' · ' + escapeHtml(j.wage) : ''}</div>
            </div>
          </div>`).join('')}
      </div>`;
  }

  const skills = ['Gardening', 'Photography', 'Housekeeping', 'Delivery', 'UI Design', 'Cooking'];
  html += `
    <div class="side-card">
      <h4>Trending in your area</h4>
      <div class="chip-cloud">
        ${skills.map((s) => `<span class="tag" data-skill="${s}">${s}</span>`).join('')}
      </div>
    </div>`;

  right.innerHTML = html;
}

function bindSidebars() {
  document.querySelectorAll('#col-left [data-left]').forEach((el) => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      const act = el.dataset.left;
      if (act === 'profile') return state.me ? goProfile(state.me.id) : showGotcha('Create an account to view your profile.');
      if (act === 'my-apps') return state.me ? goJobs('my-apps') : showGotcha('Create an account to track applications.');
      if (act === 'my-jobs') return state.me ? goJobs('my-jobs') : showGotcha('Create an account to post jobs.');
      if (act === 'nearby') return goJobs('browse');
      if (act === 'search') return goSearch('people');
    });
  });
  const sl = $('#side-login');
  if (sl) sl.addEventListener('click', () => openAuth('login'));
  const ss = $('#side-signup');
  if (ss) ss.addEventListener('click', () => openAuth('signup'));

  const cta = $('#side-complete-profile');
  if (cta) cta.addEventListener('click', (e) => { e.preventDefault(); state.me ? goProfile(state.me.id) : openAuth('signup'); });
  const ssc = $('#side-signup-cta');
  if (ssc) ssc.addEventListener('click', (e) => { e.preventDefault(); openAuth('signup'); });

  document.querySelectorAll('#col-right [data-minijob]').forEach((el) => {
    el.addEventListener('click', () => {
      const jobId = Number(el.dataset.minijob);
      if (!state.me) return showGotcha('Create an account to apply for jobs.');
      showApply(jobId);
    });
  });
  document.querySelectorAll('#col-right [data-skill]').forEach((el) => {
    el.addEventListener('click', () => goSearch('jobs', el.dataset.skill));
  });
}

function bindFeed() {
  document.querySelectorAll('[data-user]').forEach((el) => {
    el.addEventListener('click', (e) => { e.preventDefault(); goProfile(Number(el.dataset.user)); });
  });

  document.querySelectorAll('[data-lightbox]').forEach((img) => {
    img.addEventListener('click', () => showLightbox(img.dataset.lightbox));
  });

  document.querySelectorAll('[id^="like-"]').forEach((btn) => {
    if (!btn.id.startsWith('like-') || !/^\d+$/.test(btn.id.replace('like-', ''))) return;
    btn.addEventListener('click', () => {
      const postId = Number(btn.id.replace('like-', ''));
      if (!state.me) return requireLogin({ type: 'like', postId }, 'Create an account to like this post.');
      doLike(postId);
    });
  });

  document.querySelectorAll('[id^="comment-btn-"]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const postId = Number(btn.id.replace('comment-btn-', ''));
      toggleComments(postId);
      const input = $('#comment-input-' + postId);
      if (input) input.focus();
    });
  });

  document.querySelectorAll('[id^="comment-login-"]').forEach((btn) => {
    btn.addEventListener('click', () => showGotcha('Create an account to comment.'));
  });

  document.querySelectorAll('[id^="comment-input-"]').forEach((input) => {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && input.value.trim()) doComment(Number(input.id.replace('comment-input-', '')));
    });
  });

  document.querySelectorAll('[data-edit-post]').forEach((btn) => {
    btn.addEventListener('click', () => showEditPost(Number(btn.dataset.editPost)));
  });

  document.querySelectorAll('[data-delete-post]').forEach((btn) => {
    btn.addEventListener('click', () => doDeletePost(Number(btn.dataset.deletePost)));
  });

  staggerCards();
}

// ---------- Edit / Delete Posts ----------
function showEditPost(postId) {
  const postEl = document.querySelector(`[data-post="${postId}"]`);
  const bodyEl = postEl ? postEl.querySelector('.post-caption') : null;
  const currentBody = bodyEl ? bodyEl.textContent.trim() : '';
  let currentType = 'general';
  const tagEl = postEl ? postEl.querySelector('.post-tag') : null;
  if (tagEl) {
    for (const [key, meta] of Object.entries(TYPE_META)) {
      if (tagEl.textContent.trim() === meta.label) { currentType = key; break; }
    }
  }
  const imgEl = postEl ? postEl.querySelector('.post-img') : null;
  const currentImage = imgEl ? imgEl.dataset.lightbox || '' : '';

  openSheet(`
    <h2 style="margin-bottom:12px">Edit Post</h2>
    <textarea id="edit-post-body" placeholder="What's on your mind...">${escapeHtml(currentBody)}</textarea>
    <div class="type-picker" id="edit-type-picker">
      <button class="type-option ${currentType === 'general' ? 'selected' : ''}" data-type="general">📝 General</button>
      <button class="type-option ${currentType === 'offer' ? 'selected' : ''}" data-type="offer">🏷️ Offer</button>
      <button class="type-option ${currentType === 'advertisement' ? 'selected' : ''}" data-type="advertisement">📢 Advertisement</button>
    </div>
    ${currentImage ? `
      <div class="edit-image-section" style="margin-top:12px">
        <img src="${currentImage}" style="width:100%;max-height:200px;object-fit:cover;border-radius:var(--radius-sm);margin-bottom:8px" />
        <button class="btn btn-ghost btn-sm" id="edit-remove-img" style="color:var(--danger)">🗑️ Remove image</button>
      </div>` : ''}
    <div class="preview-wrap hidden" id="edit-post-preview">
      <button class="preview-remove" id="edit-preview-remove">&times;</button>
      <img id="edit-post-img" alt="" />
    </div>
    <div class="composer-actions" style="margin-top:8px">
      <label class="file-label" for="edit-post-file">🖼️ ${currentImage ? 'Change photo' : 'Add photo'}</label>
      <input type="file" id="edit-post-file" accept="image/*" class="hidden" />
    </div>
    <div class="modal-actions" style="margin-top:14px">
      <button class="btn btn-ghost" id="edit-post-cancel">Cancel</button>
      <button class="btn btn-primary" id="edit-post-save">Save</button>
    </div>
  `);

  let type = currentType;
  let editFile = null;
  const editImgPreview = $('#edit-post-preview');
  const editImgEl = $('#edit-post-img');

  $('#edit-type-picker').querySelectorAll('.type-option').forEach((b) => {
    b.addEventListener('click', () => {
      $('#edit-type-picker').querySelectorAll('.type-option').forEach((x) => x.classList.remove('selected'));
      b.classList.add('selected');
      type = b.dataset.type;
    });
  });
  $('#edit-post-cancel').addEventListener('click', closeSheet);
  $('#edit-post-file').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    editFile = file;
    editImgEl.src = URL.createObjectURL(file);
    editImgPreview.classList.remove('hidden');
  });
  $('#edit-preview-remove').addEventListener('click', () => {
    editFile = null;
    editImgPreview.classList.add('hidden');
    $('#edit-post-file').value = '';
  });
  $('#edit-remove-img').addEventListener('click', async () => {
    try {
      await api(`/api/posts/${postId}/image`, { method: 'DELETE' });
      document.querySelector('.edit-image-section')?.remove();
      toast('Image removed.');
    } catch (e) {
      toast(e.message);
    }
  });
  $('#edit-post-save').addEventListener('click', async () => {
    const text = $('#edit-post-body').value.trim();
    if (!text) { toast('Post cannot be empty.'); return; }
    const btn = $('#edit-post-save');
    btn.disabled = true;
    try {
      await api(`/api/posts/${postId}`, { method: 'PUT', body: JSON.stringify({ body: text, type }) });
      if (editFile) {
        const fd = new FormData();
        fd.append('image', editFile);
        await fetch(`/api/posts/${postId}/image`, { method: 'POST', body: fd });
      }
      closeSheet();
      toast('Post updated.');
      refreshView();
    } catch (e) {
      btn.disabled = false;
      toast(e.message);
    }
  });
  setTimeout(() => $('#edit-post-body').focus(), 50);
}

async function doDeletePost(postId) {
  if (!confirm('Are you sure you want to delete this post?')) return;
  try {
    await api(`/api/posts/${postId}`, { method: 'DELETE' });
    toast('Post deleted.');
    refreshView();
  } catch (e) {
    toast(e.message);
  }
}

// ---------- Composer ----------
function showComposer() {
  openSheet(`
    <div class="composer-head" style="margin-bottom:12px">
      ${avatar(state.me, 40)}
      <div style="font-weight:700">${escapeHtml(state.me.name)}</div>
    </div>
    <textarea id="new-post-body" placeholder="Share your business offer, advertisement or just what's on your mind..."></textarea>
    <div class="type-picker" id="type-picker">
      <button class="type-option selected" data-type="general">📝 General</button>
      <button class="type-option" data-type="offer">🏷️ Offer</button>
      <button class="type-option" data-type="advertisement">📢 Advertisement</button>
    </div>
    <div class="preview-wrap hidden" id="new-post-preview">
      <button class="preview-remove" id="preview-remove">&times;</button>
      <img id="new-post-img" alt="" />
    </div>
    <div class="composer-actions">
      <label class="file-label" for="new-post-file">🖼️ Photo</label>
      <input type="file" id="new-post-file" accept="image/*" class="hidden" />
      <button class="btn btn-ghost" id="cancel-post">Cancel</button>
      <button class="btn btn-primary" id="submit-post">Post</button>
    </div>
  `);

  let type = 'general';
  let pickedFile = null;
  const body = $('#new-post-body');
  const imgEl = $('#new-post-img');
  const preview = $('#new-post-preview');

  $('#type-picker').querySelectorAll('.type-option').forEach((b) => {
    b.addEventListener('click', () => {
      $('#type-picker').querySelectorAll('.type-option').forEach((x) => x.classList.remove('selected'));
      b.classList.add('selected');
      type = b.dataset.type;
    });
  });
  $('#new-post-file').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    pickedFile = file;
    imgEl.src = URL.createObjectURL(file);
    preview.classList.remove('hidden');
  });
  $('#preview-remove').addEventListener('click', () => {
    pickedFile = null;
    preview.classList.add('hidden');
    $('#new-post-file').value = '';
  });
  $('#cancel-post').addEventListener('click', closeSheet);
  $('#submit-post').addEventListener('click', () => {
    const text = body.value.trim();
    if (!text && !pickedFile) { toast('Write something first!'); return; }
    doCreatePost(text, pickedFile, type);
  });
  body.focus();
}

async function doCreatePost(text, image, type) {
  const btn = $('#submit-post');
  if (btn) btn.disabled = true;
  try {
    const data = await api('/api/posts', { method: 'POST', body: JSON.stringify({ body: text, type }) });
    if (image) {
      const fd = new FormData();
      fd.append('image', image);
      await fetch(`/api/posts/${data.id}/image`, { method: 'POST', body: fd });
    }
    closeSheet();
    await loadFeed();
    toast('Posted!');
  } catch (e) {
    if (btn) btn.disabled = false;
    if (e.message.includes('sign in')) {
      state.pendingAction = { type: 'post', text, image };
      showGotcha('Create an account to write a post.');
    } else toast(e.message);
  }
}

// ---------- Likes / comments ----------
async function doLike(postId) {
  const btn = $('#like-' + postId);
  const wasLiked = btn && btn.textContent.includes('Liked');
  const data = await api(`/api/posts/${postId}/${wasLiked ? 'unlike' : 'like'}`, { method: 'POST' });
  const count = $('#like-count-' + postId);
  if (count) { count.textContent = data.likeCount; count.classList.remove('pop-pop'); void count.offsetWidth; count.classList.add('pop-pop'); }
  if (btn) {
    btn.innerHTML = `<span class="btn-ico">${data.liked ? ICONS.heartFilled : ICONS.heart}</span> ${data.liked ? 'Liked' : 'Like'}`;
    btn.classList.toggle('liked', data.liked);
    btn.classList.remove('pop-pop'); void btn.offsetWidth; btn.classList.add('pop-pop');
  }
}

async function toggleComments(postId) {
  const box = $('#comments-' + postId);
  if (!box) return;
  if (box.dataset.loaded) return box.classList.toggle('hidden');
  box.innerHTML = '<div class="spinner" style="padding:16px">Loading...</div>';
  box.classList.remove('hidden');
  const data = await api(`/api/posts/${postId}/comments`);
  box.dataset.loaded = '1';
  renderComments(box, data.comments);
  box.querySelectorAll('[data-user]').forEach((el) => {
    el.addEventListener('click', (e) => { e.preventDefault(); goProfile(Number(el.dataset.user)); });
  });
}

function renderComments(box, comments) {
  if (!comments.length) {
    box.innerHTML = '<div style="color:var(--text-soft);font-size:14px;padding:4px 0 8px">No comments yet.</div>';
    return;
  }
  box.innerHTML = comments.map((c) => `
    <div class="comment">
      ${avatar(c.author, 32)}
      <div class="comment-bubble">
        <a href="#" class="comment-author" data-user="${c.author.id}">${escapeHtml(c.author.name)}</a>
        <div class="comment-text">${escapeHtml(c.body)}</div>
      </div>
    </div>
  `).join('');
}

async function doComment(postId, presetText) {
  const input = $('#comment-input-' + postId);
  const text = (presetText || (input && input.value) || '').trim();
  if (!text) return;
  const data = await api(`/api/posts/${postId}/comments`, { method: 'POST', body: JSON.stringify({ body: text }) });
  const box = $('#comments-' + postId);
  if (box) { box.dataset.loaded = ''; box.classList.remove('hidden'); }
  if (input) input.value = '';
  state.pendingAction = null;
  const count = $('#comment-count-' + postId);
  if (count) { const n = parseInt(count.textContent, 10) + 1; count.textContent = n; }
  if (box) { const res = await api(`/api/posts/${postId}/comments`); renderComments(box, res.comments); }
}

// =====================================================================
// NOTIFICATIONS
// =====================================================================
async function loadNotifications() {
  if (!state.me) return;
  try {
    const data = await api('/api/notifications');
    state.notifications = data.notifications || [];
    state.notificationsUnread = data.unread || 0;
    updateNotifBadge();
  } catch (e) { /* silent */ }
}

function updateNotifBadge() {
  const badge = $('#notif-badge');
  if (!badge) return;
  if (state.notificationsUnread > 0) {
    badge.textContent = state.notificationsUnread;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

function showNotifications() {
  if (!state.me) return showGotcha('Sign in to see notifications.');
  toggleNotifPanel();
}

function pollNotifications() {
  stopNotifPoll();
  state.notifPollTimer = setInterval(() => {
    if (state.me) loadNotifications();
  }, 15000);
}

function stopNotifPoll() {
  if (state.notifPollTimer) {
    clearInterval(state.notifPollTimer);
    state.notifPollTimer = null;
  }
}

// =====================================================================
// MESSAGES
// =====================================================================
const CHAT_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '😡', '🎉', '🔥', '👏', '💯'];
let chatReplyTo = null;
let chatEditId = null;
let chatTargetUserId = null;
let chatTypingTimer = null;
let chatAllMessages = [];
let chatIsMuted = false;
let chatIsBlocked = false;
let chatForwardMsg = null;

function stopChatTyping() {
  if (chatTypingTimer) { clearInterval(chatTypingTimer); chatTypingTimer = null; }
}

function formatChatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const msgDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const diff = today - msgDay;
  if (diff < 86400000 && now.getDate() === d.getDate()) return 'Today';
  if (diff < 172800000) return 'Yesterday';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined });
}

function readReceiptHtml(m) {
  if (!m || !m.senderId || !state.me || m.senderId !== state.me.id) return '';
  if (m.read) return '<span class="chat-read-receipt read"><svg width="16" height="10" viewBox="0 0 16 10" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 5.5l3 3 5-6"/><path d="M6 5.5l3 3 5-6"/></svg></span>';
  if (m.delivered) return '<span class="chat-read-receipt"><svg width="16" height="10" viewBox="0 0 16 10" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 5.5l3 3 5-6"/><path d="M6 5.5l3 3 5-6"/></svg></span>';
  return '<span class="chat-read-receipt"><svg width="14" height="10" viewBox="0 0 14 10" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 5.5l3 3 5-6"/></svg></span>';
}

function chatReactionsHtml(m) {
  if (!m.reactions || !Object.keys(m.reactions).length) return '';
  const chips = Object.entries(m.reactions).map(([emoji, data]) => {
    const active = data.userIds && state.me && data.userIds.includes(state.me.id);
    return `<button class="reaction-chip ${active ? 'active' : ''}" data-msg-id="${m.id}" data-react-emoji="${emoji}">${emoji} <span>${data.count}</span></button>`;
  }).join('');
  return `<div class="reactions-bar">${chips}</div>`;
}

function chatMsgHtml(m) {
  const isMe = state.me && m.senderId === state.me.id;
  const isDeleted = m.deleted;
  const time = m.createdAt ? new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
  const replyHtml = m.replyTo ? `<div class="chat-reply-quote"><span class="chat-reply-name">${escapeHtml(m.replyTo.senderName || '')}</span>${escapeHtml((m.replyTo.body || '').slice(0, 80))}${(m.replyTo.body || '').length > 80 ? '…' : ''}</div>` : '';
  const editedTag = m.edited ? ' <span class="chat-edited">(edited)</span>' : '';
  const forwardedTag = m.forwarded ? '<div class="forwarded-tag">Forwarded</div>' : '';
  const reactionsHtml = chatReactionsHtml(m);
  const receiptHtml = isMe ? readReceiptHtml(m) : '';
  const emojiPickerHtml = `<div class="msg-reaction-picker" data-msg-id="${m.id}">${CHAT_EMOJIS.slice(0, 6).map((e) => `<button data-add-reaction="${m.id}" data-emoji="${e}">${e}</button>`).join('')}</div>`;

  let attachmentHtml = '';
  if (m.image) {
    attachmentHtml = `<div class="chat-attachment"><img src="${escapeHtml(m.image)}" alt="" onclick="showLightbox('${escapeHtml(m.image)}')" /></div>`;
  } else if (m.fileUrl) {
    const fname = m.fileName || 'File';
    attachmentHtml = `<div class="chat-attachment"><a class="file-link" href="${escapeHtml(m.fileUrl)}" target="_blank" rel="noopener">📎 ${escapeHtml(fname)}</a></div>`;
  }

  if (isDeleted) {
    return `
      <div class="chat-msg ${isMe ? 'chat-msg-me' : 'chat-msg-them'}" data-msg-id="${m.id}">
        ${!isMe ? avatar(m.sender, 28) : ''}
        <div class="chat-msg-content">
          <div class="chat-bubble chat-bubble-deleted"><em>This message was deleted.</em></div>
        </div>
        ${isMe ? avatar(m.sender, 28) : ''}
      </div>`;
  }

  const isOwn = isMe;
  const editBtn = isOwn ? `<button class="chat-action-btn" data-msg-action="edit" data-msg-id="${m.id}" title="Edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg></button>` : '';
  const deleteBtn = isOwn ? `<button class="chat-action-btn chat-action-delete" data-msg-action="delete" data-msg-id="${m.id}" title="Delete"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>` : '';

  const actionsHtml = `
    <div class="chat-msg-actions">
      <button class="chat-action-btn" data-msg-action="reply" data-msg-id="${m.id}" title="Reply"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 14 4 9 9 4"></polyline><path d="M20 20v-7a4 4 0 0 0-4-4H4"></path></svg></button>
      <button class="chat-action-btn" data-msg-action="react" data-msg-id="${m.id}" title="React">😀</button>
      <button class="chat-action-btn" data-msg-action="star" data-msg-id="${m.id}" title="Star">${m.starred ? '⭐' : '☆'}</button>
      <button class="chat-action-btn" data-msg-action="forward" data-msg-id="${m.id}" title="Forward"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13"></path><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg></button>
      ${editBtn}
      ${deleteBtn}
    </div>`;

  return `
    <div class="chat-msg ${isMe ? 'chat-msg-me' : 'chat-msg-them'}" data-msg-id="${m.id}">
      ${!isMe ? avatar(m.sender, 28) : ''}
      <div class="chat-msg-content">
        ${emojiPickerHtml}
        ${forwardedTag}
        ${replyHtml}
        ${attachmentHtml}
        <div class="chat-bubble">${escapeHtml(m.body || '')}${editedTag}${receiptHtml}</div>
        <div class="chat-msg-meta">
          <span class="chat-msg-time">${time}</span>
          ${actionsHtml}
        </div>
        ${reactionsHtml}
      </div>
      ${isMe ? avatar(m.sender, 28) : ''}
    </div>`;
}

function chatDateSepHtml(label) {
  return `<div class="chat-date-sep"><span>${label}</span></div>`;
}

function buildChatMessagesHtml(messages) {
  const parts = [];
  let lastDateKey = '';
  messages.forEach((m) => {
    const d = m.createdAt ? new Date(m.createdAt) : null;
    const dateKey = d ? `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}` : '';
    if (dateKey && dateKey !== lastDateKey) {
      parts.push(chatDateSepHtml(formatChatDate(m.createdAt)));
      lastDateKey = dateKey;
    }
    parts.push(chatMsgHtml(m));
  });
  return parts.join('');
}

async function goMessages() {
  if (!state.me) return showGotcha('Sign in to view messages.');
  state.currentView = 'messages';
  setActiveNav('messages');
  document.body.classList.add('narrow');
  stopChatTyping();
  chatForwardMsg = null;
  app.innerHTML = '<div class="spinner">Loading messages...</div>';
  try {
    const data = await api('/api/messages');
    const convos = data.conversations || [];
    if (!convos.length) {
      app.innerHTML = '<div class="empty">No conversations yet. Visit someone\'s profile to start chatting.</div>';
      viewEnter();
      return;
    }
    app.innerHTML = `
      <div class="card" style="padding:16px">
        <h2 style="font-family:var(--font-display);font-size:22px;font-weight:800;margin-bottom:14px">Messages</h2>
      </div>
      <div class="convo-list">
        ${convos.map((c) => {
          const other = c.other;
          const unreadCount = c.unreadCount || 0;
          const online = other.online;
          const muted = c.muted;
          const lastPreview = c.lastMessage || '';
          const isFromMe = c.lastSenderId === state.me.id;
          const previewText = isFromMe ? `You: ${lastPreview}` : lastPreview;
          return `
            <div class="convo-item card" data-chat="${other.id}" style="cursor:pointer">
              <div class="convo-inner">
                <div style="position:relative;flex-shrink:0">
                  ${avatar(other, 48)}
                  ${online ? '<div class="online-dot"></div>' : ''}
                </div>
                <div class="convo-info">
                  <div class="convo-name">${escapeHtml(other.name)}${muted ? ' <span class="muted-icon">🔇</span>' : ''}</div>
                  <div class="convo-preview">${escapeHtml(previewText)}</div>
                </div>
                <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0">
                  <div class="convo-time">${c.lastMessageAt ? timeAgo(c.lastMessageAt) : ''}</div>
                  ${unreadCount > 0 ? `<div class="convo-unread">${unreadCount}</div>` : ''}
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
    document.querySelectorAll('[data-chat]').forEach((el) => {
      el.addEventListener('click', () => openChat(Number(el.dataset.chat)));
    });
    viewEnter();
  } catch (e) {
    app.innerHTML = `<div class="empty">${e.message}</div>`;
  }
}

async function openChat(userId) {
  if (!state.me) return showGotcha('Sign in to chat.');
  state.currentView = 'chat';
  chatTargetUserId = userId;
  chatReplyTo = null;
  chatEditId = null;
  chatForwardMsg = null;
  app.innerHTML = '<div class="spinner">Loading chat...</div>';
  try {
    const data = await api(`/api/messages/${userId}`);
    const messages = data.messages || [];
    chatAllMessages = messages;
    const otherUser = data.other || { id: userId, name: 'User' };
    chatIsMuted = !!data.muted;
    chatIsBlocked = !!data.blocked;

    const unreadMsgIds = messages.filter((m) => !m.read && m.senderId !== state.me.id).map((m) => m.id);
    if (unreadMsgIds.length) {
      api(`/api/messages/read`, { method: 'POST', body: JSON.stringify({ messageIds: unreadMsgIds }) }).catch(() => {});
    }

    app.innerHTML = `
      <div class="chat-view">
        <div class="chat-header">
          <button class="btn btn-ghost btn-sm" id="chat-back" style="padding:6px 10px">←</button>
          <div style="display:flex;align-items:center;gap:10px;cursor:pointer;flex:1;min-width:0" data-user="${userId}">
            <div style="position:relative;flex-shrink:0">
              ${avatar(otherUser, 36)}
              ${otherUser.online ? '<div class="online-dot"></div>' : ''}
            </div>
            <div style="min-width:0">
              <div style="font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(otherUser.name)}</div>
              <div style="font-size:11px;color:var(--text-3)">${otherUser.online ? 'Online' : 'Offline'}</div>
            </div>
          </div>
          <div class="chat-options">
            <button class="btn btn-ghost btn-sm" id="chat-options-btn" style="padding:6px 10px">⋮</button>
            <div class="chat-options-menu" id="chat-options-menu">
              <button id="chat-search-btn">🔍 Search in chat</button>
              <button id="chat-starred-btn">⭐ Starred messages</button>
              <button id="chat-mute-btn">${chatIsMuted ? '🔊 Unmute' : '🔇 Mute'}</button>
              <button id="chat-block-btn" style="color:var(--danger)">${chatIsBlocked ? '✓ Unblock user' : '🚫 Block user'}</button>
              <button id="chat-clear-btn" style="color:var(--danger)">🗑️ Clear chat</button>
            </div>
          </div>
        </div>
        <div class="chat-search-bar hidden" id="chat-search-bar">
          <input type="text" id="chat-search-q" placeholder="Search messages..." autocomplete="off" />
          <button class="btn btn-ghost btn-sm" id="chat-search-close">✕</button>
        </div>
        <div class="chat-messages" id="chat-messages">
          ${messages.length ? buildChatMessagesHtml(messages) : '<div class="empty" style="border:none;box-shadow:none;padding:40px">No messages yet. Say hello!</div>'}
        </div>
        <div class="chat-reply-bar hidden" id="chat-reply-bar">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 14 4 9 9 4"></polyline><path d="M20 20v-7a4 4 0 0 0-4-4H4"></path></svg>
          <span id="chat-reply-text"></span>
          <button class="chat-reply-cancel" id="chat-reply-cancel">×</button>
        </div>
        <div class="typing-indicator hidden" id="typing-indicator">
          <div class="typing-dots"><span></span><span></span><span></span></div>
          <span>${escapeHtml(otherUser.name)} is typing...</span>
        </div>
        <div class="chat-input-bar">
          <div class="chat-input-extras" style="position:relative">
            <button class="chat-extra-btn" id="chat-emoji-btn" title="Emoji">😊</button>
            <div class="emoji-picker hidden" id="chat-emoji-picker">
              ${CHAT_EMOJIS.map((e) => `<button data-emoji-pick="${e}">${e}</button>`).join('')}
            </div>
            <label class="chat-extra-btn" id="chat-attach-label" title="Attach file" style="cursor:pointer">
              📎
              <input type="file" id="chat-attach-file" accept="image/*,.pdf,.doc,.docx,.txt" style="display:none" />
            </label>
          </div>
          <input type="text" id="chat-input" placeholder="Type a message..." autocomplete="off" ${chatIsBlocked ? 'disabled' : ''} />
          <button class="btn btn-primary" id="chat-send" ${chatIsBlocked ? 'disabled' : ''}>Send</button>
        </div>
      </div>
    `;

    const msgBox = $('#chat-messages');
    if (msgBox) msgBox.scrollTop = msgBox.scrollHeight;

    $('#chat-back').addEventListener('click', goMessages);
    document.querySelectorAll('[data-user]').forEach((el) => {
      el.addEventListener('click', (e) => { e.preventDefault(); goProfile(Number(el.dataset.user)); });
    });

    // Options menu toggle
    $('#chat-options-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      $('#chat-options-menu').classList.toggle('open');
    });
    document.addEventListener('click', () => $('#chat-options-menu').classList.remove('open'));

    // Search in chat
    $('#chat-search-btn').addEventListener('click', () => {
      $('#chat-search-bar').classList.toggle('hidden');
      $('#chat-options-menu').classList.remove('open');
      if (!$('#chat-search-bar').classList.contains('hidden')) $('#chat-search-q').focus();
    });
    $('#chat-search-close').addEventListener('click', () => {
      $('#chat-search-bar').classList.add('hidden');
      $('#chat-search-q').value = '';
      filterChatMessages('');
    });
    $('#chat-search-q').addEventListener('input', debounce((e) => {
      filterChatMessages(e.target.value.trim().toLowerCase());
    }, 250));

    // Starred messages
    $('#chat-starred-btn').addEventListener('click', () => {
      $('#chat-options-menu').classList.remove('open');
      showStarredMessages(userId);
    });

    // Mute
    $('#chat-mute-btn').addEventListener('click', () => {
      $('#chat-options-menu').classList.remove('open');
      toggleMuteChat(userId);
    });

    // Block
    $('#chat-block-btn').addEventListener('click', () => {
      $('#chat-options-menu').classList.remove('open');
      blockUser(userId);
    });

    // Clear chat
    $('#chat-clear-btn').addEventListener('click', () => {
      $('#chat-options-menu').classList.remove('open');
      clearChat(userId);
    });

    // Message actions delegation
    msgBox.addEventListener('click', (e) => {
      // Reaction picker toggle
      const reactionPicker = e.target.closest('.msg-reaction-picker button');
      if (reactionPicker) {
        const msgId = Number(reactionPicker.dataset.addReaction);
        const emoji = reactionPicker.dataset.emoji;
        if (msgId && emoji) addReaction(msgId, emoji);
        return;
      }

      // Reaction chip click
      const reactionChip = e.target.closest('.reaction-chip');
      if (reactionChip) {
        const msgId = Number(reactionChip.dataset.msgId);
        const emoji = reactionChip.dataset.reactEmoji;
        if (msgId && emoji) addReaction(msgId, emoji);
        return;
      }

      const btn = e.target.closest('[data-msg-action]');
      if (!btn) return;
      const action = btn.dataset.msgAction;
      const msgId = Number(btn.dataset.msgId);
      if (action === 'delete') deleteChatMessage(msgId);
      else if (action === 'edit') startEditMessage(msgId, messages);
      else if (action === 'reply') startReplyMessage(msgId, messages);
      else if (action === 'forward') startForwardMessage(msgId, messages);
      else if (action === 'star') toggleStarMessage(msgId);
      else if (action === 'react') toggleInlineReactionPicker(btn, msgId);
    });

    // Reply cancel
    $('#chat-reply-cancel').addEventListener('click', () => {
      chatReplyTo = null;
      $('#chat-reply-bar').classList.add('hidden');
      $('#chat-reply-text').textContent = '';
    });

    // Emoji picker
    $('#chat-emoji-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      $('#chat-emoji-picker').classList.toggle('hidden');
    });
    document.querySelectorAll('[data-emoji-pick]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const input = $('#chat-input');
        input.value += btn.dataset.emojiPick;
        input.focus();
        $('#chat-emoji-picker').classList.add('hidden');
      });
    });

    // File attach
    $('#chat-attach-file').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) handleChatFileAttach(file, userId);
      e.target.value = '';
    });

    // Send
    const sendMsg = () => sendMessage(userId);
    $('#chat-send').addEventListener('click', sendMsg);
    $('#chat-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
    });

    // Typing indicator polling
    startTypingPoll(userId);

    setTimeout(() => { if (!$('#chat-input')?.disabled) $('#chat-input')?.focus(); }, 50);
    viewEnter();
  } catch (e) {
    app.innerHTML = `<div class="empty">${e.message}</div>`;
  }
}

function filterChatMessages(query) {
  const msgs = document.querySelectorAll('#chat-messages [data-msg-id]');
  if (!query) {
    msgs.forEach((el) => el.style.display = '');
    document.querySelectorAll('#chat-messages .chat-date-sep').forEach((el) => el.style.display = '');
    return;
  }
  msgs.forEach((el) => {
    const bubble = el.querySelector('.chat-bubble');
    const text = bubble ? bubble.textContent.toLowerCase() : '';
    el.style.display = text.includes(query) ? '' : 'none';
  });
}

function startTypingPoll(userId) {
  stopChatTyping();
  chatTypingTimer = setInterval(async () => {
    try {
      const data = await api(`/api/messages/${userId}/typing`);
      const ind = $('#typing-indicator');
      if (ind) {
        if (data.typing) ind.classList.remove('hidden');
        else ind.classList.add('hidden');
      }
    } catch { /* silent */ }
  }, 3000);
}

function toggleInlineReactionPicker(btn, msgId) {
  const existing = document.querySelector('.inline-reaction-popup');
  if (existing) { existing.remove(); return; }
  const popup = document.createElement('div');
  popup.className = 'inline-reaction-popup emoji-picker';
  popup.style.cssText = 'position:absolute;top:-60px;left:50%;transform:translateX(-50%);z-index:60';
  popup.innerHTML = CHAT_EMOJIS.map((e) => `<button data-add-reaction="${msgId}" data-emoji="${e}">${e}</button>`).join('');
  popup.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-add-reaction]');
    if (b) {
      addReaction(Number(b.dataset.addReaction), b.dataset.emoji);
      popup.remove();
    }
  });
  btn.closest('.chat-msg-content')?.appendChild(popup);
  setTimeout(() => document.addEventListener('click', function closePopup(ev) {
    if (!popup.contains(ev.target) && ev.target !== btn) { popup.remove(); document.removeEventListener('click', closePopup); }
  }, { once: true }), 10);
}

async function addReaction(msgId, emoji) {
  try {
    const data = await api(`/api/messages/${msgId}/react`, { method: 'POST', body: JSON.stringify({ emoji }) });
    if (data.message) {
      const msgIdx = chatAllMessages.findIndex((m) => m.id === msgId);
      if (msgIdx >= 0) chatAllMessages[msgIdx].reactions = data.message.reactions || {};
      const el = document.querySelector(`[data-msg-id="${msgId}"]`);
      if (el) {
        const reactionsContainer = el.querySelector('.reactions-bar');
        const newHtml = chatReactionsHtml(chatAllMessages[msgIdx] || { reactions: {} });
        if (reactionsContainer) reactionsContainer.outerHTML = newHtml;
        else el.querySelector('.chat-msg-content')?.insertAdjacentHTML('beforeend', newHtml);
      }
    }
  } catch (e) { toast(e.message); }
}

async function toggleStarMessage(msgId) {
  try {
    const data = await api(`/api/messages/${msgId}/star`, { method: 'POST' });
    const msgIdx = chatAllMessages.findIndex((m) => m.id === msgId);
    if (msgIdx >= 0) chatAllMessages[msgIdx].starred = data.starred;
    toast(data.starred ? 'Message starred' : 'Message unstarred');
    const starBtn = document.querySelector(`[data-msg-id="${msgId}"] [data-msg-action="star"]`);
    if (starBtn) starBtn.textContent = data.starred ? '⭐' : '☆';
  } catch (e) { toast(e.message); }
}

function startReplyMessage(msgId, messages) {
  const msg = messages.find((m) => m.id === msgId);
  if (!msg) return;
  chatReplyTo = msg;
  chatEditId = null;
  chatForwardMsg = null;
  const bar = $('#chat-reply-bar');
  const text = $('#chat-reply-text');
  text.textContent = `Replying to ${msg.sender?.name || 'User'}: ${(msg.body || '').slice(0, 60)}${(msg.body || '').length > 60 ? '…' : ''}`;
  bar.classList.remove('hidden');
  $('#chat-input').focus();
}

function startEditMessage(msgId, messages) {
  const msg = messages.find((m) => m.id === msgId);
  if (!msg || msg.senderId !== state.me.id) return;
  chatEditId = msgId;
  chatReplyTo = null;
  chatForwardMsg = null;
  const input = $('#chat-input');
  input.value = (msg.body || '').replace('(edited)', '').trim();
  input.focus();
}

function startForwardMessage(msgId, messages) {
  const msg = messages.find((m) => m.id === msgId);
  if (!msg) return;
  chatForwardMsg = msg;
  chatReplyTo = null;
  chatEditId = null;
  showForwardPicker(msg);
}

async function showForwardPicker(msg) {
  openSheet(`
    <h2 style="margin-bottom:12px">Forward message</h2>
    <p class="modal-sub" style="margin-bottom:12px">Select a conversation to forward this message to.</p>
    <div id="forward-search-wrap" style="margin-bottom:12px">
      <input type="text" id="forward-search" placeholder="Search people..." style="width:100%;border:1px solid var(--border);border-radius:8px;padding:10px;font-size:14px;font-family:inherit;background:var(--surface-3);color:var(--text)" />
    </div>
    <div id="forward-list" style="max-height:300px;overflow-y:auto">
      <div class="spinner">Loading...</div>
    </div>
    <div class="modal-actions"><button class="btn btn-ghost" id="forward-cancel">Cancel</button></div>
  `);
  $('#forward-cancel').addEventListener('click', closeSheet);
  try {
    const data = await api('/api/messages');
    const convos = data.conversations || [];
    const list = $('#forward-list');
    function renderForwardList(filter) {
      const filtered = filter ? convos.filter((c) => c.other.name.toLowerCase().includes(filter.toLowerCase())) : convos;
      list.innerHTML = filtered.length ? filtered.map((c) => `
        <div class="convo-item" data-forward-to="${c.other.id}" style="cursor:pointer;padding:10px;border-radius:8px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)">
          ${avatar(c.other, 36)}
          <div style="font-weight:600;font-size:14px">${escapeHtml(c.other.name)}</div>
        </div>
      `).join('') : '<div style="padding:12px;color:var(--text-3);text-align:center;font-size:13px">No conversations found</div>';
      list.querySelectorAll('[data-forward-to]').forEach((el) => {
        el.addEventListener('click', () => {
          doForwardMessage(Number(el.dataset.forwardTo), msg);
          closeSheet();
        });
      });
    }
    renderForwardList('');
    $('#forward-search').addEventListener('input', (e) => renderForwardList(e.target.value.trim()));
  } catch (e) {
    $('#forward-list').innerHTML = '<div class="empty">Failed to load conversations</div>';
  }
}

async function doForwardMessage(targetUserId, msg) {
  try {
    await api(`/api/messages/${targetUserId}`, { method: 'POST', body: JSON.stringify({ body: msg.body || '', forwarded: true, forwardOriginalId: msg.id }) });
    toast('Message forwarded!');
    chatForwardMsg = null;
  } catch (e) { toast(e.message); }
}

async function showStarredMessages(userId) {
  openSheet(`
    <h2 style="margin-bottom:12px">Starred Messages</h2>
    <div class="starred-panel" id="starred-panel"><div class="spinner">Loading...</div></div>
    <div class="modal-actions"><button class="btn btn-ghost" id="starred-close">Close</button></div>
  `);
  $('#starred-close').addEventListener('click', closeSheet);
  const starred = chatAllMessages.filter((m) => m.starred);
  const panel = $('#starred-panel');
  if (!starred.length) {
    panel.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-3);font-size:13px">No starred messages.</div>';
  } else {
    panel.innerHTML = starred.map((m) => `
      <div class="starred-msg">
        <div style="font-size:12px;color:var(--text-3);margin-bottom:4px">${escapeHtml(m.sender?.name || 'User')} · ${m.createdAt ? timeAgo(m.createdAt) : ''}</div>
        <div>${escapeHtml(m.body || '')}</div>
      </div>
    `).join('');
  }
}

async function toggleMuteChat(userId) {
  try {
    const data = await api(`/api/messages/${userId}/mute`, { method: 'POST' });
    chatIsMuted = data.muted;
    toast(data.muted ? 'Chat muted' : 'Chat unmuted');
    const muteBtn = $('#chat-mute-btn');
    if (muteBtn) muteBtn.textContent = chatIsMuted ? '🔊 Unmute' : '🔇 Mute';
  } catch (e) { toast(e.message); }
}

async function blockUser(userId) {
  const action = chatIsBlocked ? 'unblock' : 'block';
  if (!confirm(chatIsBlocked ? 'Unblock this user?' : 'Block this user? They won\'t be able to message you.')) return;
  try {
    const data = await api(`/api/messages/${userId}/block`, { method: 'POST' });
    chatIsBlocked = data.blocked;
    toast(data.blocked ? 'User blocked' : 'User unblocked');
    const blockBtn = $('#chat-block-btn');
    if (blockBtn) blockBtn.textContent = chatIsBlocked ? '✓ Unblock user' : '🚫 Block user';
    const input = $('#chat-input');
    const sendBtn = $('#chat-send');
    if (input) input.disabled = chatIsBlocked;
    if (sendBtn) sendBtn.disabled = chatIsBlocked;
  } catch (e) { toast(e.message); }
}

async function clearChat(userId) {
  if (!confirm('Clear all messages in this chat? This cannot be undone.')) return;
  try {
    await api(`/api/messages/${userId}/clear`, { method: 'DELETE' });
    chatAllMessages = [];
    const msgBox = $('#chat-messages');
    if (msgBox) msgBox.innerHTML = '<div class="empty" style="border:none;box-shadow:none;padding:40px">No messages yet. Say hello!</div>';
    toast('Chat cleared');
  } catch (e) { toast(e.message); }
}

async function handleChatFileAttach(file, userId) {
  const fd = new FormData();
  fd.append('file', file);
  try {
    const res = await fetch(`/api/messages/${userId}/upload`, { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Upload failed');
    const body = { body: '' };
    if (data.image) body.image = data.image;
    if (data.fileUrl) { body.fileUrl = data.fileUrl; body.fileName = file.name; }
    const msgData = await api(`/api/messages/${userId}`, { method: 'POST', body: JSON.stringify(body) });
    const msgBox = $('#chat-messages');
    if (msgBox) {
      const emptyMsg = msgBox.querySelector('.empty');
      if (emptyMsg) emptyMsg.remove();
      chatAllMessages.push(msgData.message);
      msgBox.insertAdjacentHTML('beforeend', chatMsgHtml(msgData.message));
      msgBox.scrollTop = msgBox.scrollHeight;
    }
  } catch (e) { toast(e.message); }
}

async function deleteChatMessage(msgId) {
  if (!confirm('Delete this message?')) return;
  try {
    await api(`/api/messages/${msgId}`, { method: 'DELETE' });
    const msgEl = document.querySelector(`[data-msg-id="${msgId}"]`);
    if (msgEl) {
      const bubble = msgEl.querySelector('.chat-bubble');
      if (bubble) {
        bubble.innerHTML = '<em>This message was deleted.</em>';
        bubble.classList.add('chat-bubble-deleted');
      }
      const actions = msgEl.querySelector('.chat-msg-actions');
      if (actions) actions.remove();
      const picker = msgEl.querySelector('.msg-reaction-picker');
      if (picker) picker.remove();
      const attach = msgEl.querySelector('.chat-attachment');
      if (attach) attach.remove();
    }
    const msgIdx = chatAllMessages.findIndex((m) => m.id === msgId);
    if (msgIdx >= 0) chatAllMessages[msgIdx].deleted = true;
    toast('Message deleted');
  } catch (e) {
    toast(e.message);
  }
}

async function sendMessage(userId) {
  const input = $('#chat-input');
  if (!input) return;
  const text = input.value.trim();
  if (!text && !chatForwardMsg) return;

  if (chatEditId) {
    input.value = '';
    try {
      await api(`/api/messages/${chatEditId}`, { method: 'PATCH', body: JSON.stringify({ body: text }) });
      const msgEl = document.querySelector(`[data-msg-id="${chatEditId}"] .chat-bubble`);
      if (msgEl) {
        const receiptHtml = readReceiptHtml({ senderId: state.me.id });
        msgEl.innerHTML = escapeHtml(text) + ' <span class="chat-edited">(edited)</span>' + receiptHtml;
      }
      const msgIdx = chatAllMessages.findIndex((m) => m.id === chatEditId);
      if (msgIdx >= 0) { chatAllMessages[msgIdx].body = text; chatAllMessages[msgIdx].edited = true; }
      chatEditId = null;
      toast('Message edited');
    } catch (e) {
      toast(e.message);
      input.value = text;
    }
    return;
  }

  const body = { body: text };
  if (chatReplyTo) { body.replyToId = chatReplyTo.id; chatReplyTo = null; $('#chat-reply-bar').classList.add('hidden'); $('#chat-reply-text').textContent = ''; }

  input.value = '';
  try {
    const data = await api(`/api/messages/${userId}`, { method: 'POST', body: JSON.stringify(body) });
    const msgBox = $('#chat-messages');
    if (msgBox) {
      const emptyMsg = msgBox.querySelector('.empty');
      if (emptyMsg) emptyMsg.remove();
      chatAllMessages.push(data.message);
      msgBox.insertAdjacentHTML('beforeend', chatMsgHtml(data.message));
      msgBox.scrollTop = msgBox.scrollHeight;
    }
  } catch (e) {
    toast(e.message);
    input.value = text;
  }
}

// =====================================================================
// SEARCH
// =====================================================================
function goSearch(type, q) {
  state.currentView = 'search';
  setActiveNav('search');
  document.body.classList.add('narrow');
  const val = q !== undefined ? q : ($('#search-q') ? $('#search-q').value : '');
  renderSearch(val, type || 'people');
}

function renderSearch(q, type = 'people') {
  app.innerHTML = `
    <div class="card" style="padding:16px">
      <div class="job-toolbar" style="margin-bottom:0">
        <input type="text" id="search-q" value="${escapeHtml(q)}" placeholder="Search accounts, businesses, jobs..." />
      </div>
      <div class="section-tabs" style="margin-top:12px">
        <a data-type="people" class="${type === 'people' ? 'active' : ''}">People</a>
        <a data-type="business" class="${type === 'business' ? 'active' : ''}">Businesses</a>
        <a data-type="jobs" class="${type === 'jobs' ? 'active' : ''}">Jobs</a>
      </div>
    </div>
    <div class="results" id="search-results" style="margin-top:16px">${q ? '<div class="spinner">Searching...</div>' : '<div class="hintbar">Search for people, businesses or jobs by name, email, skills or keywords.</div>'}</div>
  `;
  document.querySelectorAll('.section-tabs a').forEach((a) => {
    a.addEventListener('click', () => {
      const t = a.dataset.type;
      const val = $('#search-q').value;
      state.__searchType = t;
      state.__searchQ = val;
      renderSearch(val, t);
      if (val.trim()) doSearch(val, t);
    });
  });
  $('#search-q').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.value.trim()) {
      const t = document.querySelector('.section-tabs a.active').dataset.type;
      doSearch(e.target.value.trim(), t);
    }
  });
  $('#search-q').addEventListener('input', debounce((e) => {
    const val = e.target.value.trim();
    const t = document.querySelector('.section-tabs a.active').dataset.type;
    if (val.length >= 2) doSearch(val, t);
    else if (!val) $('#search-results').innerHTML = '<div class="hintbar">Search for people, businesses or jobs by name, email, skills or keywords.</div>';
  }, 300));
  if (q.trim()) doSearch(q, type);
  viewEnter();
}

async function doSearch(q, type) {
  const box = $('#search-results');
  if (!box) return;
  box.innerHTML = '<div class="spinner">Searching...</div>';
  const data = await api('/api/search?type=' + type + '&q=' + encodeURIComponent(q));
  if (type === 'jobs') {
    box.innerHTML = data.results.length
      ? data.results.map(jobHtml).join('')
      : '<div class="empty">No jobs found.</div>';
    bindJobCards(box);
  } else {
    box.innerHTML = data.results.length
      ? data.results.map((u) => `
        <div class="result-card">
          ${avatar(u, 44)}
          <div class="info">
            <a href="#" class="result-name" data-user="${u.id}">${escapeHtml(u.name)} ${u.role === 'owner' ? '<span class="post-tag general">Business</span>' : ''}</a>
            <div class="result-sub">${escapeHtml(u.email)}</div>
            ${u.skills.length ? `<div class="result-sub" style="margin-top:4px">Skills: ${u.skills.map(escapeHtml).join(', ')}</div>` : ''}
            ${u.bio ? `<div class="result-sub">${escapeHtml(u.bio)}</div>` : ''}
          </div>
          <button class="btn btn-primary" data-view-user="${u.id}">View</button>
        </div>`).join('')
      : '<div class="empty">No people found.</div>';
    box.querySelectorAll('[data-user]').forEach((el) => {
      el.addEventListener('click', (e) => { e.preventDefault(); goProfile(Number(el.dataset.user)); });
    });
    box.querySelectorAll('[data-view-user]').forEach((el) => {
      el.addEventListener('click', () => goProfile(Number(el.dataset.viewUser)));
    });
  }
}

// =====================================================================
// PROFILE
// =====================================================================
async function goProfile(userId) {
  state.currentView = 'profile';
  state.profileUserId = userId;
  setActiveNav(null);
  document.body.classList.add('narrow');
  app.innerHTML = '<div class="spinner">Loading profile...</div>';
  try {
    const data = await api(`/api/users/${userId}`);
    const isMe = state.me && state.me.id === userId;
    const headline = data.user.role === 'owner'
      ? 'Business · Open to hiring'
      : (data.user.skills.length ? data.user.skills.slice(0, 2).join(' · ') : 'Job seeker');
    const memberSince = data.user.createdAt ? new Date(data.user.createdAt).toLocaleDateString('en-US', { month: 'short', year: 'numeric' }) : '';
    const totalEngagement = data.likesReceived + data.commentsReceived + data.postCount;

    app.innerHTML = `
      <div class="profile-dash">
        <div class="profile-top card">
          <div class="cover-banner"></div>
          <div class="profile-head">
            ${avatar(data.user, 120)}
            <div class="profile-head-main">
              <div class="profile-name">${escapeHtml(data.user.name)} ${data.user.role === 'owner' ? '<span class="post-tag general">Business</span>' : ''}</div>
              <div class="profile-headline">${escapeHtml(headline)}</div>
              <div class="profile-sub">${escapeHtml(data.user.email || '')}${data.user.role === 'owner' ? ' · ' + escapeHtml(data.user.bio ? data.user.bio.slice(0, 60) + '…' : '') : ''}</div>
              <div class="profile-sub" style="margin-top:2px">${memberSince ? '📅 Joined ' + memberSince : ''}</div>
              ${data.user.role === 'owner' ? `<div style="margin-top:8px"><span class="pill" style="color:#48566a;background:#e8edf3;border-color:#cbd5e1">Open to hiring</span></div>` : (state.me && state.me.id !== userId ? `<div style="margin-top:8px"><span class="pill" style="color:#48566a;background:#e8edf3;border-color:#cbd5e1">Open to work</span></div>` : '')}
              <div class="profile-actions">
                ${isMe ? `<button class="btn btn-soft" id="profile-edit-btn"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path></svg> Edit profile</button>` : ''}
                ${!isMe && state.me ? `<button class="btn btn-primary" id="profile-msg-btn">💬 Message</button>` : ''}
              </div>
            </div>
          </div>
          <div class="profile-stats">
            <div class="stat"><div class="stat-num">${data.postCount}</div><div class="stat-label">Posts</div></div>
            <div class="stat"><div class="stat-num">${data.likesReceived}</div><div class="stat-label">Likes</div></div>
            <div class="stat"><div class="stat-num">${data.commentsReceived}</div><div class="stat-label">Comments</div></div>
            ${data.user.role === 'owner' ? `<div class="stat"><div class="stat-num">${data.openJobs}</div><div class="stat-label">Open jobs</div></div>` : ''}
          </div>
        </div>

        <div class="profile-dash-grid">
          <div class="profile-main">
            <div class="card profile-section">
              <h3 class="section-title">About</h3>
              <p class="section-text">${escapeHtml(data.user.bio || 'No bio yet.')}</p>
            </div>
            <div class="card profile-section">
              <h3 class="section-title">Skills</h3>
              ${data.user.skills.length
                ? `<div class="skills-row">${data.user.skills.map((s) => `<span class="skill-chip">${escapeHtml(s)}</span>`).join('')}</div>`
                : '<p style="color:var(--text-soft);font-size:14px">No skills added yet.</p>'}
            </div>
            <div class="card profile-section">
              <h3 class="section-title">Activity</h3>
              <div id="profile-posts">${data.posts.map(postHtml).join('') || '<p style="color:var(--text-soft)">No posts yet.</p>'}</div>
            </div>
          </div>
          <div class="profile-side">
            <div class="card profile-section">
              <h3 class="section-title">${isMe ? 'Your analytics' : 'Overview'}</h3>
              <div class="analytics-row"><div class="analytics-label">Engagement</div><div class="analytics-val">${totalEngagement}</div></div>
              <div class="analytics-row"><div class="analytics-label">Member since</div><div class="analytics-val">${memberSince || '—'}</div></div>
              <div class="analytics-row"><div class="analytics-label">Role</div><div class="analytics-val">${data.user.role === 'owner' ? 'Business' : 'Individual'}</div></div>
              ${data.user.role === 'owner' ? `<div class="analytics-row"><div class="analytics-label">Completed jobs</div><div class="analytics-val">${data.jobsDone}</div></div>` : ''}
            </div>
            <div class="card profile-section about-card">
              <h3 class="section-title">Profile tips</h3>
              <p style="color:var(--text-soft);font-size:13px;line-height:1.5">${isMe
                ? 'Complete your profile with skills and a bio to get more job offers and connections.'
                : 'Add this person to reach out about jobs or opportunities.'}</p>
            </div>
          </div>
        </div>
      </div>
    `;
    bindFeed();
    if (isMe) bindProfileEdit(data.user);
    if (!isMe && state.me) {
      const msgBtn = $('#profile-msg-btn');
      if (msgBtn) msgBtn.addEventListener('click', () => openChat(userId));
    }
    viewEnter();
  } catch (e) {
    app.innerHTML = `<div class="empty">${e.message}</div>`;
  }
}

function bindProfileEdit(user) {
  const wrap = document.querySelector('.profile-top');
  $('#profile-edit-btn').addEventListener('click', () => {
    wrap.insertAdjacentHTML('beforeend', `
      <div class="profile-edit">
        <div style="text-align:center;margin-bottom:12px">
          <label class="file-label" for="edit-photo" style="display:inline-block">📷 Change photo</label>
          <input type="file" id="edit-photo" accept="image/*" class="hidden" />
          <div id="edit-photo-preview" style="margin-top:8px"></div>
        </div>
        <input type="text" id="edit-name" value="${escapeHtml(user.name)}" style="width:100%;border:1px solid var(--border);border-radius:8px;padding:10px;font-size:14px;margin-bottom:8px" />
        <textarea id="edit-bio" placeholder="Add a short bio...">${escapeHtml(user.bio || '')}</textarea>
        <input type="text" id="edit-skills" value="${escapeHtml((user.skills || []).join(', '))}" placeholder="Skills (comma separated, e.g. Barista, Driving)" style="width:100%;border:1px solid var(--border);border-radius:8px;padding:10px;font-size:14px;margin-top:8px" />
        <div style="display:flex;gap:8px;margin-top:8px;justify-content:flex-end">
          <button class="btn btn-ghost" id="edit-cancel">Cancel</button>
          <button class="btn btn-primary" id="edit-save">Save</button>
        </div>
      </div>
    `);

    let pickedPhoto = null;
    const previewDiv = $('#edit-photo-preview');
    $('#edit-photo').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      pickedPhoto = file;
      previewDiv.innerHTML = `<img src="${URL.createObjectURL(file)}" style="width:80px;height:80px;border-radius:50%;object-fit:cover;border:3px solid var(--border)" />`;
    });

    $('#edit-cancel').addEventListener('click', () => document.querySelector('.profile-edit').remove());
    $('#edit-save').addEventListener('click', async () => {
      const name = $('#edit-name').value.trim();
      const bio = $('#edit-bio').value;
      const skills = $('#edit-skills').value.split(',').map((s) => s.trim()).filter(Boolean);
      const saveBtn = $('#edit-save');
      saveBtn.disabled = true;
      try {
        await api(`/api/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ name, bio, skills }) });
        if (pickedPhoto) {
          const fd = new FormData();
          fd.append('photo', pickedPhoto);
          await fetch(`/api/users/${user.id}/photo`, { method: 'POST', body: fd });
        }
        state.me = (await api('/api/me')).user;
        renderAuth();
        goProfile(user.id);
        toast('Profile updated.');
      } catch (e) {
        saveBtn.disabled = false;
        toast(e.message);
      }
    });
  });
}

// =====================================================================
// JOBS
// =====================================================================
function goJobs(tab) {
  state.currentView = 'jobs';
  setActiveNav('jobs');
  document.body.classList.add('narrow');
  state.jobsTab = tab || state.jobsTab || 'browse';
  const tabs = `
    <div class="section-tabs">
      <a data-tab="browse" class="${state.jobsTab === 'browse' ? 'active' : ''}">Browse Jobs</a>
      ${state.me ? `
        <a data-tab="my-apps" class="${state.jobsTab === 'my-apps' ? 'active' : ''}">My Applications</a>
        <a data-tab="my-jobs" class="${state.jobsTab === 'my-jobs' ? 'active' : ''}">My Posted Jobs</a>` : ''}
    </div>`;
  app.innerHTML = tabs + '<div id="jobs-body">' + (state.jobsTab === 'browse' ? jobBrowseHtml() : '<div class="spinner">Loading...</div>') + '</div>';
  document.querySelectorAll('.section-tabs a').forEach((a) => {
    a.addEventListener('click', () => goJobs(a.dataset.tab));
  });
  if (state.jobsTab === 'browse') bindJobBrowse();
  else if (state.jobsTab === 'my-apps') loadMyApplications();
  else loadMyJobs();
  viewEnter();
}

function jobBrowseHtml() {
  return `
    <div class="card" style="padding:16px">
      <div class="job-toolbar">
        <input type="text" id="job-q" placeholder="Search title, keyword, category..." />
        <input type="number" id="job-radius" placeholder="km radius" min="1" max="500" style="flex:0 0 110px" />
        <button class="btn btn-primary" id="job-search-btn">Search</button>
        <button class="btn btn-ghost" id="job-nearby-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> Nearby</button>
      </div>
      ${state.me ? `<div style="text-align:right"><button class="btn btn-green" id="job-post-btn">+ Post a Job</button></div>` : '<div style="text-align:right;color:var(--text-soft);font-size:13px">Sign in to post a job or apply.</div>'}
    </div>
    <div class="results" id="job-results" style="margin-top:16px"><div class="hintbar">Browse jobs or search to find something nearby. Enable Nearby to sort by distance from you.</div></div>
  `;
}

function bindJobBrowse() {
  const search = () => {
    const q = $('#job-q').value.trim();
    const radius = $('#job-radius').value.trim();
    fetchJobs({ q, radius, nearby: false });
  };
  $('#job-search-btn').addEventListener('click', search);
  $('#job-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') search(); });
  $('#job-q').addEventListener('input', debounce(() => search(), 300));
  $('#job-nearby-btn').addEventListener('click', nearbyJobs);
  if (state.me) $('#job-post-btn').addEventListener('click', showPostJob);
  fetchJobs({});
}

function nearbyJobs() {
  if (!navigator.geolocation) { toast('Geolocation not supported.'); return; }
  if (!state.me) { showGotcha('Create an account to use Nearby jobs.'); return; }
  const radius = $('#job-radius').value.trim();
  $('#job-results').innerHTML = '<div class="spinner">Locating your position...</div>';
  navigator.geolocation.getCurrentPosition(
    (pos) => fetchJobs({ lat: pos.coords.latitude, lng: pos.coords.longitude, radius: radius || 50, nearby: true }),
    () => { $('#job-results').innerHTML = '<div class="empty">Could not get your location. Allow location access or search by keyword instead.</div>'; },
    { timeout: 10000 }
  );
}

async function fetchJobs(filters) {
  const box = $('#job-results');
  if (!box) { goJobs('browse'); return; }
  box.innerHTML = '<div class="spinner">Loading jobs...</div>';
  const params = new URLSearchParams();
  if (filters.q) params.set('q', filters.q);
  if (filters.nearby && filters.lat) { params.set('nearby', '1'); params.set('lat', filters.lat); params.set('lng', filters.lng); params.set('radius', filters.radius || 50); }
  const data = await api('/api/jobs?' + params.toString());
  box.innerHTML = data.jobs.length
    ? data.jobs.map(jobHtml).join('')
    : '<div class="empty">No jobs found. Try widening the search.</div>';
  bindJobCards(box);
}

function jobHtml(j) {
  let status = '';
  if (state.me && j.myStatus) {
    status = `<span class="job-status ${j.myStatus}">${j.myStatus === 'accepted' ? 'Accepted' : j.myStatus === 'rejected' ? 'Rejected' : 'Applied'}</span>`;
  }
  return `
    <div class="card job-card" data-job="${j.id}">
      <div class="job-title">${escapeHtml(j.title)} ${j.filled ? '<span class="job-status accepted">Filled</span>' : status}</div>
      <div class="job-meta">
        <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg> ${escapeHtml(j.category || 'General')}</span>
        ${j.wage ? `<span>💰 ${escapeHtml(j.wage)}</span>` : ''}
        ${j.locationText ? `<span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> ${escapeHtml(j.locationText)}</span>` : ''}
        <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> ${escapeHtml(j.giver.name)}</span>
        <span>🗓️ ${timeAgo(j.createdAt)}</span>
      </div>
      ${j.description ? `<div class="job-desc">${escapeHtml(j.description)}</div>` : ''}
      <div style="display:flex;justify-content:flex-end;margin-top:12px">
        <button class="btn btn-primary" data-apply="${j.id}">Apply</button>
      </div>
    </div>
  `;
}

function bindJobCards(scope) {
  scope.querySelectorAll('[data-apply]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const jobId = Number(btn.dataset.apply);
      if (!state.me) return requireLogin({ type: 'apply', jobId }, 'Create an account to apply for jobs.');
      showApply(jobId);
    });
  });
}

function showApply(jobId) {
  openSheet(`
    <h2 style="margin-bottom:12px">Apply for this job</h2>
    <p class="modal-sub" style="margin-bottom:12px">Add a short message to the job giver. They'll see your bio and skills from your profile.</p>
    <textarea id="apply-message" placeholder="Tell them why you're a good fit..." style="width:100%;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:15px;font-family:inherit;resize:vertical;min-height:100px"></textarea>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="apply-cancel">Cancel</button>
      <button class="btn btn-primary" id="apply-submit">Apply</button>
    </div>
  `);
  $('#apply-cancel').addEventListener('click', closeSheet);
  $('#apply-submit').addEventListener('click', async () => {
    await doApply(jobId, $('#apply-message').value.trim());
  });
}

async function doApply(jobId) {
  const message = $('#apply-message') ? $('#apply-message').value.trim() : '';
  const btn = $('#apply-submit');
  if (btn) btn.disabled = true;
  try {
    await api(`/api/jobs/${jobId}/apply`, { method: 'POST', body: JSON.stringify({ message }) });
    closeSheet();
    state.pendingAction = null;
    toast('Application sent!');
    goJobs('my-apps');
  } catch (e) {
    if (btn) btn.disabled = false;
    if (e.message.includes('sign in')) {
      state.pendingAction = { type: 'apply', jobId };
      showGotcha('Create an account to apply for jobs.');
    } else toast(e.message);
  }
}

function showPostJob() {
  state._pendingJobLat = null;
  state._pendingJobLng = null;
  openSheet(`
    <h2 style="margin-bottom:16px">Post a job</h2>
    <input type="text" id="job-title" placeholder="Job title *" style="width:100%;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:15px;margin-bottom:12px" />
    <textarea id="job-desc" placeholder="Description" style="width:100%;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:15px;font-family:inherit;resize:vertical;min-height:90px;margin-bottom:12px"></textarea>
    <div style="display:flex;gap:10px;margin-bottom:12px">
      <input type="text" id="job-cat" placeholder="Category (e.g. Food & Beverage)" style="flex:1;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:15px" />
      <input type="text" id="job-wage" placeholder="Wage (e.g. ₹150/day)" style="flex:1;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:15px" />
    </div>
    <div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">
      <input type="text" id="job-loc" placeholder="Area / city (e.g. Bandra, Mumbai)" style="flex:1;border:1px solid var(--border);border-radius:8px;padding:12px;font-size:15px" />
      <button class="btn btn-ghost" id="job-detect-btn" style="white-space:nowrap"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> Auto-detect</button>
    </div>
    <button class="btn btn-primary btn-block" id="job-create">Post Job</button>
  `);
  $('#job-detect-btn').addEventListener('click', async () => {
    if (!navigator.geolocation) { toast('Geolocation not supported.'); return; }
    toast('Detecting location...');
    navigator.geolocation.getCurrentPosition(async (pos) => {
      const { latitude: lat, longitude: lng } = pos.coords;
      state._pendingJobLat = lat;
      state._pendingJobLng = lng;
      try {
        const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`);
        const geo = await res.json();
        const city = geo.address?.city || geo.address?.town || geo.address?.village || '';
        const area = geo.address?.suburb || geo.address?.neighbourhood || '';
        $('#job-loc').value = [area, city].filter(Boolean).join(', ') || `${lat.toFixed(4)}, ${lng.toFixed(4)}`;
        toast('Location detected!');
      } catch { toast('Could not reverse geocode. Coordinates saved.'); }
    }, () => toast('Could not get your location.'), { timeout: 10000 });
  });
  $('#job-create').addEventListener('click', async () => {
    const title = $('#job-title').value.trim();
    if (!title) { toast('Job title is required.'); return; }
    await api('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({
        title,
        description: $('#job-desc').value.trim(),
        category: $('#job-cat').value.trim(),
        wage: $('#job-wage').value.trim(),
        locationText: $('#job-loc').value.trim(),
        lat: state._pendingJobLat || undefined,
        lng: state._pendingJobLng || undefined,
      }),
    });
    closeSheet();
    toast('Job posted!');
    goJobs('my-jobs');
  });
}

async function loadMyApplications() {
  const box = $('#jobs-body');
  box.innerHTML = '<div class="spinner">Loading...</div>';
  const data = await api('/api/my/applications');
  box.innerHTML = data.jobs.length
    ? data.jobs.map((j) => `
      <div class="card job-card">
        <div class="job-title">${escapeHtml(j.title)} <span class="job-status ${j.appStatus}">${escapeHtml(j.appStatus)}</span></div>
        <div class="job-meta">
          <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> ${escapeHtml(j.giver.name)}</span>
          ${j.wage ? `<span>💰 ${escapeHtml(j.wage)}</span>` : ''}
          ${j.locationText ? `<span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> ${escapeHtml(j.locationText)}</span>` : ''}
          <span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg> Applied ${timeAgo(j.appliedAt)}</span>
        </div>
        ${j.description ? `<div class="job-desc">${escapeHtml(j.description)}</div>` : ''}
      </div>`).join('')
    : '<div class="empty">You have not applied to any jobs yet. Go to Browse Jobs to find one.</div>';
}

async function loadMyJobs() {
  const box = $('#jobs-body');
  box.innerHTML = '<div class="spinner">Loading...</div>';
  const data = await api('/api/my/jobs');
  box.innerHTML = (data.jobs.length ? '' : '<div class="hintbar">You have not posted any jobs yet.</div>') +
    data.jobs.map((j) => `
      <div class="card">
        <div class="job-card">
          <div class="job-title">${escapeHtml(j.title)} ${j.filled ? '<span class="job-status accepted">Filled</span>' : ''}</div>
          <div class="job-meta">
            <span>👥 ${j.applicantCount} applicants</span>
            ${j.wage ? `<span>💰 ${escapeHtml(j.wage)}</span>` : ''}
          ${j.locationText ? `<span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> ${escapeHtml(j.locationText)}</span>` : ''}
          </div>
        </div>
        <div style="padding:0 16px 16px;display:flex;justify-content:flex-end">
          <button class="btn btn-primary" data-applicants="${j.id}">View Applicants</button>
        </div>
      </div>`).join('');
  box.querySelectorAll('[data-applicants]').forEach((btn) => {
    btn.addEventListener('click', () => showApplicants(Number(btn.dataset.applicants)));
  });
}

async function showApplicants(jobId) {
  const data = await api(`/api/jobs/${jobId}/applications`);
  openSheet(`
    <h2 style="margin-bottom:4px">Applicants</h2>
    <p class="modal-sub" style="margin-bottom:12px">Review each candidate's skills and bio before accepting.</p>
    ${data.applications.length ? data.applications.map((a) => `
      <div class="applicant" data-appl="${a.id}">
        <div class="applicant-head">
          ${avatar(a.seeker, 40)}
          <div>
            <a href="#" class="applicant-name" data-user="${a.seeker.id}">${escapeHtml(a.seeker.name)}</a>
            <span class="job-status ${a.status}">${escapeHtml(a.status)}</span>
          </div>
        </div>
        ${a.seeker.skills.length ? `<div class="skills-row">${a.seeker.skills.map((s) => `<span class="skill-chip">${escapeHtml(s)}</span>`).join('')}</div>` : ''}
        ${a.seeker.bio ? `<div class="applicant-bio">${escapeHtml(a.seeker.bio)}</div>` : ''}
        ${a.message ? `<div class="applicant-bio" style="margin-top:4px">💬 ${escapeHtml(a.message)}</div>` : ''}
        ${a.status === 'pending' ? `
          <div class="applicant-actions">
            <button class="btn btn-ghost" data-decide="${a.id}" data-act="reject">Reject</button>
            <button class="btn btn-green" data-decide="${a.id}" data-act="accept">Accept</button>
          </div>` : ''}
      </div>`).join('')
    : '<div class="empty">No applicants yet.</div>'}
    <div class="modal-actions"><button class="btn btn-ghost" id="appl-close">Close</button></div>
  `);
  $('#appl-close').addEventListener('click', closeSheet);
  document.querySelectorAll('#sheet-body [data-decide]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      await api(`/api/applications/${btn.dataset.decide}/decide`, { method: 'POST', body: JSON.stringify({ decision: btn.dataset.act }) });
      toast(btn.dataset.act === 'accept' ? 'Candidate accepted. Job filled.' : 'Candidate rejected.');
      showApplicants(jobId);
    });
  });
  document.querySelectorAll('#sheet-body [data-user]').forEach((el) => {
    el.addEventListener('click', (e) => { e.preventDefault(); closeSheet(); goProfile(Number(el.dataset.user)); });
  });
}

// =====================================================================
// MAP VIEW
// =====================================================================
let mapInstance = null;
let mapMarkers = null;
let mapUserMarker = null;

function goMap() {
  state.currentView = 'map';
  setActiveNav('map');
  document.body.classList.add('narrow');
  app.innerHTML = `
    <div class="map-toolbar">
      <select id="map-category"><option value="">All Categories</option></select>
      <select id="map-radius">
        <option value="">Any distance</option>
        <option value="2">Within 2 km</option>
        <option value="5">Within 5 km</option>
        <option value="10">Within 10 km</option>
        <option value="25">Within 25 km</option>
        <option value="50">Within 50 km</option>
      </select>
      <button class="btn btn-primary" id="map-filter-btn">Filter</button>
      <button class="btn btn-ghost" id="map-reset-btn">Reset</button>
      <div style="flex:1"></div>
      <span class="map-info-count" id="map-count"></span>
    </div>
    <div class="map-container" id="map-wrap">
      <div id="job-map"></div>
      <button class="map-locate-btn" id="map-locate" title="Find my location"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg></button>
    </div>
    <div class="map-legend">
      <div class="map-legend-item"><span class="map-legend-dot" style="background:#48566a"></span> Open Job</div>
      <div class="map-legend-item"><span class="map-legend-dot" style="background:#94a3b8"></span> Filled</div>
      <div class="map-legend-item"><span class="map-legend-dot" style="background:#e5484d"></span> Your Location</div>
    </div>
  `;
  initMap();
  viewEnter();
}

function initMap() {
  if (mapInstance) { mapInstance.remove(); mapInstance = null; }
  mapInstance = L.map('job-map', { zoomControl: false }).setView([19.076, 72.8777], 12);
  L.control.zoom({ position: 'bottomright' }).addTo(mapInstance);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    maxZoom: 19,
  }).addTo(mapInstance);
  mapMarkers = L.featureGroup().addTo(mapInstance);
  loadMapJobs();

  $('#map-filter-btn').addEventListener('click', () => loadMapJobs());
  $('#map-reset-btn').addEventListener('click', () => {
    $('#map-category').value = '';
    $('#map-radius').value = '';
    loadMapJobs();
    if (mapUserMarker) { mapInstance.setView(mapUserMarker.getLatLng(), 13); }
    else { mapInstance.setView([19.076, 72.8777], 12); }
  });
  $('#map-locate').addEventListener('click', locateMe);
}

function markerIcon(filled) {
  const cls = filled ? 'marker-filled' : 'marker-open';
  const emoji = filled ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>';
  return L.divIcon({
    className: 'job-marker',
    html: `<div class="job-marker-inner ${cls}"><span>${emoji}</span></div>`,
    iconSize: [36, 42],
    iconAnchor: [18, 42],
    popupAnchor: [0, -42],
  });
}

function locateMe() {
  if (!navigator.geolocation) { toast('Geolocation not supported.'); return;
  }
  toast('Locating...');
  navigator.geolocation.getCurrentPosition((pos) => {
    const { latitude: lat, longitude: lng } = pos.coords;
    if (mapUserMarker) mapInstance.removeLayer(mapUserMarker);
    mapUserMarker = L.marker([lat, lng], {
      icon: L.divIcon({
        className: 'job-marker',
        html: '<div class="job-marker-inner marker-my"><span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg></span></div>',
        iconSize: [36, 42],
        iconAnchor: [18, 42],
      }),
    }).addTo(mapInstance).bindPopup('<b>You are here</b>');
    mapInstance.setView([lat, lng], 13);
    toast('Location found!');
  }, () => toast('Could not get your location.'), { timeout: 10000 });
}

function loadMapJobs() {
  const category = $('#map-category').value;
  const radius = $('#map-radius').value;
  let url = '/api/jobs/map?';
  if (category) url += 'category=' + encodeURIComponent(category) + '&';
  if (radius && state._mapLat) {
    url += 'lat=' + state._mapLat + '&lng=' + state._mapLng + '&radius=' + radius;
  }
  api(url).then((data) => {
    if (mapMarkers) mapMarkers.clearLayers();
    data.jobs.forEach((j) => {
      const marker = L.marker([j.lat, j.lng], { icon: markerIcon(j.filled) });
      const tag = TYPE_META[j.type] || TYPE_META.general;
      const desc = j.description
        ? `<div class="map-popup-desc">${escapeHtml(j.description)}</div>`
        : '';
      const inner = `
        <div class="map-popup">
          <div class="map-popup-title">${escapeHtml(j.title)}</div>
          <div class="map-popup-meta">
            ${j.category ? `<span class="map-popup-chip">${escapeHtml(j.category)}</span>` : ''}
            ${j.wage ? `<span class="map-popup-chip">💰 ${escapeHtml(j.wage)}</span>` : ''}
            ${j.filled ? '<span class="map-popup-chip" style="color:var(--text-soft)">Filled</span>' : ''}
          </div>
          ${desc}
          <div class="map-popup-giver">
            ${avatar(j.giver, 22)} ${escapeHtml(j.giver.name)} · ${escapeHtml(j.locationText || '')}
          </div>
          <div class="map-popup-actions">
            <button class="btn btn-ghost" onclick="closeMapPopup(); goProfile(${j.giver.id});">Profile</button>
            ${!j.filled && state.me && state.me.id !== j.giver.id
              ? `<button class="btn btn-primary" onclick="closeMapPopup(); showApply(${j.id});">Apply</button>`
              : ''
            }
          </div>
        </div>
      `;
      marker.bindPopup(inner, { maxWidth: 280 });
      mapMarkers.addLayer(marker);
    });
    const count = $('#map-count');
    if (count) count.textContent = data.jobs.length + ' job' + (data.jobs.length !== 1 ? 's' : '') + ' shown';
    const cats = $('#map-category');
    if (cats && cats.options.length <= 1 && data.categories.length) {
      data.categories.forEach((c) => { const o = document.createElement('option'); o.value = c; o.textContent = c; cats.appendChild(o); });
    }
    if (mapMarkers.getLayers().length > 0) {
      mapInstance.fitBounds(mapMarkers.getBounds().pad(0.15));
    }
  }).catch(() => toast('Failed to load map jobs.'));
}

function closeMapPopup() { if (mapInstance) mapInstance.closePopup(); }

// =============================================================
// Unique animations
// =============================================================

// Cursor glow follows the mouse
function initCursorGlow() {
  const glow = $('#cursor-glow');
  if (!glow) return;
  let raf = null;
  let targetX = 0, targetY = 0, x = 0, y = 0;
  window.addEventListener('mousemove', (e) => {
    targetX = e.clientX; targetY = e.clientY;
    glow.style.opacity = '1';
    if (!raf) raf = requestAnimationFrame(loop);
  });
  document.addEventListener('mouseleave', () => { glow.style.opacity = '0'; });
  function loop() {
    x += (targetX - x) * 0.12;
    y += (targetY - y) * 0.12;
    glow.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`;
    if (Math.abs(targetX - x) > 0.5 || Math.abs(targetY - y) > 0.5) raf = requestAnimationFrame(loop);
    else raf = null;
  }
}

// Staggered entrance for feed cards
function staggerCards(scope) {
  const cards = (scope || document).querySelectorAll('.feed-stagger');
  cards.forEach((card, i) => {
    card.style.animationDelay = `${Math.min(i * 0.07, 0.7)}s`;
  });
}

// 3D tilt on post cards
function applyTilt() {
  function isPost(el) { return el && el.classList && el.classList.contains('post'); }
  document.querySelectorAll('.tilt-inner').forEach((el) => {
    let raf = null;
    el.parentElement.addEventListener('mousemove', (e) => {
      if (isPost(el.parentElement)) el.parentElement.style.zIndex = '5';
      const r = el.parentElement.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width - 0.5;
      const py = (e.clientY - r.top) / r.height - 0.5;
      const ty = px * 7, tx = -py * 7;
      if (!raf) raf = requestAnimationFrame(() => {
        el.style.transform = `perspective(900px) rotateY(${ty}deg) rotateX(${tx}deg) scale(1.01)`;
        raf = null;
      });
    });
    el.parentElement.addEventListener('mouseleave', () => {
      el.style.transform = 'perspective(900px) rotateY(0deg) rotateX(0deg) scale(1)';
      if (isPost(el.parentElement)) el.parentElement.style.zIndex = '';
    });
  });
}

// Emoji particle burst from a point
function burstEmojis(x, y, emojis, count = 12) {
  for (let i = 0; i < count; i++) {
    const s = document.createElement('span');
    s.className = 'like-burst';
    s.textContent = emojis[Math.floor(Math.random() * emojis.length)];
    s.style.left = x + 'px';
    s.style.top = y + 'px';
    const angle = (Math.PI * 2 * i) / count + Math.random() * 0.6;
    const dist = 60 + Math.random() * 80;
    s.style.setProperty('--dx', Math.cos(angle) * dist + 'px');
    s.style.setProperty('--dy', (Math.sin(angle) * dist - 40) + 'px');
    s.style.setProperty('--rot', (Math.random() * 260 - 130) + 'deg');
    document.body.appendChild(s);
    setTimeout(() => s.remove(), 950);
  }
}

// Magnetic hover on buttons
function initMagnetic() {
  document.querySelectorAll('.btn').forEach((btn) => {
    btn.addEventListener('mousemove', (e) => {
      if (btn.disabled) return;
      const r = btn.getBoundingClientRect();
      const dx = e.clientX - (r.left + r.width / 2);
      const dy = e.clientY - (r.top + r.height / 2);
      btn.style.transform = `translate(${dx * 0.15}px, ${dy * 0.2}px)`;
    });
    btn.addEventListener('mouseleave', () => { btn.style.transform = ''; });
  });
}

// Re-trigger view entrance animation
function viewEnter() {
  const el = app;
  el.classList.remove('view-enter');
  void el.offsetWidth;
  el.classList.add('view-enter');
}

// ---------- Routing ----------
function goFeed() { document.title = 'ANNOUNCE'; loadFeed(); }

function refreshView() {
  if (state.currentView === 'profile' && state.profileUserId) goProfile(state.profileUserId);
  else if (state.currentView === 'jobs') goJobs();
  else if (state.currentView === 'search') goSearch();
  else if (state.currentView === 'messages' || state.currentView === 'chat') goMessages();
  else if (state.currentView === 'map') goMap();
  else loadFeed();
}

// ---------- Nav ----------
document.querySelectorAll('[data-nav]').forEach((el) => {
  el.addEventListener('click', (e) => {
    e.preventDefault();
    const nav = el.dataset.nav;
    if (nav === 'feed') goFeed();
    else if (nav === 'search') goSearch();
    else if (nav === 'jobs') goJobs('browse');
    else if (nav === 'map') goMap();
    else if (nav === 'messages') goMessages();
  });
});

// ---------- Init ----------
document.addEventListener('click', (e) => {
  const nearNotif = e.target.closest('.notif-wrap');
  const nearMe = e.target.closest('.me-wrap');
  const np = $('#notif-panel');
  const mp = $('#me-panel');
  if (np && np.classList.contains('open') && !nearNotif) np.classList.remove('open');
  if (mp && mp.classList.contains('open') && !nearMe) mp.classList.remove('open');
});

(async function init() {
  const data = await api('/api/me');
  state.me = data.user;
  renderAuth();
  goFeed();
  if (state.me) pollNotifications();
})();
