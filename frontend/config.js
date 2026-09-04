(function () {
  const defaults = {
    API_BASE_URL: 'https://bchat-app-production.up.railway.app',
    SUPABASE_URL: 'https://kvcrlmfltbpnnjvrghtw.supabase.co',
    SUPABASE_ANON_KEY: 'sb_publishable_VIzSz8dD8xQMrrn1RuQgYw_W8Sn1rRE'
  };

  const runtime = {
    API_BASE_URL: window.__BCHAT_CONFIG__?.API_BASE_URL || defaults.API_BASE_URL,
    SUPABASE_URL: window.__BCHAT_CONFIG__?.SUPABASE_URL || defaults.SUPABASE_URL,
    SUPABASE_ANON_KEY: window.__BCHAT_CONFIG__?.SUPABASE_ANON_KEY || defaults.SUPABASE_ANON_KEY
  };

  window.__BCHAT_CONFIG__ = runtime;
})();
