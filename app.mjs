import { decryptPayload } from './crypto.mjs';

export function dashboardDocument(html, data, channel) {
  const safeData = JSON.stringify(data).replaceAll('<', '\\u003c');
  const dataTag = `<script>window.SSQ_DATA = ${safeData};</script>`;
  const embedded = html.replace(/<script\s+src="data\.js"[^>]*>\s*<\/script>/, () => dataTag)
    .replace(/<form method="post" action="\/logout">[\s\S]*?<\/form>/, '<button class="logout" type="button" id="private-logout">退出登录</button>');
  if (embedded === html || !embedded.includes('id="private-logout"')) throw new Error('Dashboard template cannot be embedded');
  const policy = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'; img-src data:; connect-src \'none\'; form-action \'none\'; base-uri \'none\'">';
  const bridge = `<script>(()=>{const channel=${JSON.stringify(channel)};
    const send=()=>parent.postMessage({type:'ssq-height',channel,height:document.documentElement.scrollHeight},'*');
    document.getElementById('private-logout').addEventListener('click',()=>parent.postMessage({type:'ssq-lock',channel},'*'));
    new ResizeObserver(send).observe(document.body);send();})();</script>`;
  return embedded.replace('<head>', '<head>' + policy).replace('</body>', bridge + '</body>');
}

function initialize() {
  const entry = document.getElementById('entry'), dashboard = document.getElementById('dashboard');
  const form = document.getElementById('unlock-form'), password = document.getElementById('password');
  const button = document.getElementById('unlock'), status = document.getElementById('status');
  let activeFrame = null, activeChannel = null;
  function lock() {
    activeFrame?.remove();
    activeFrame = null; activeChannel = null;
    dashboard.replaceChildren(); dashboard.hidden = true; entry.hidden = false;
    password.value = ''; status.textContent = ''; button.disabled = false; button.textContent = '解锁看板';
  }
  window.addEventListener('message', event => {
    if (event.source !== activeFrame?.contentWindow || event.data?.channel !== activeChannel) return;
    if (event.data.type === 'ssq-lock') lock();
    if (event.data.type === 'ssq-height' && Number.isFinite(event.data.height)) {
      activeFrame.style.height = `${Math.min(Math.max(event.data.height + 8, 500), 100_000)}px`;
    }
  });
  window.addEventListener('pagehide', lock);
  window.addEventListener('pageshow', event => { if (event.persisted) lock(); });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!crypto?.subtle) { status.textContent = '请使用支持HTTPS的现代浏览器打开此页面。'; return; }
    button.disabled = true; button.textContent = '正在解锁…'; status.textContent = '';
    let envelope;
    try {
      const response = await fetch(new URL('payload.json', import.meta.url), { cache: 'no-store', credentials: 'omit' });
      if (!response.ok) throw new Error('Encrypted data unavailable');
      envelope = await response.json();
    } catch {
      status.textContent = '加密数据暂时无法加载，请刷新后重试。';
      button.disabled = false; button.textContent = '解锁看板'; return;
    }
    try {
      const input = password.value;
      password.value = '';
      const value = await decryptPayload(envelope, input);
      const channel = crypto.randomUUID();
      const frame = document.createElement('iframe');
      frame.title = '私人号码看板内容';
      frame.setAttribute('sandbox', 'allow-scripts allow-popups');
      frame.referrerPolicy = 'no-referrer';
      frame.srcdoc = dashboardDocument(value.html, value.data, channel);
      activeFrame = frame; activeChannel = channel;
      dashboard.replaceChildren(frame); entry.hidden = true; dashboard.hidden = false;
    } catch {
      status.textContent = '密码不正确，或加密文件已损坏。请确认密码后重试。';
    } finally { button.disabled = false; button.textContent = '解锁看板'; }
  });
}
if (typeof document !== 'undefined') initialize();
