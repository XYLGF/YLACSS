export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*", // 允许 bbs.ylai.website 跨域请求
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    // 密码加密哈希的辅助函数
    async function hashPassword(password) {
      const msgBuffer = new TextEncoder().encode(password);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    try {
      // 1. 发送验证码 (使用 Resend)
      if (request.method === "POST" && url.pathname === "/api/send-code") {
        const { email } = await request.json();
        if (!email) return new Response("邮箱不能为空", { status: 400, headers: corsHeaders });

        const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6位随机码
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5分钟有效

        // 存入数据库
        await env.DB.prepare("INSERT OR REPLACE INTO verify_codes (email, code, expires_at) VALUES (?, ?, ?)").bind(email, code, expiresAt).run();

        // 调用 Resend 发邮件
        const res = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.RESEND_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            from: "YL Accounts <no-reply@xylplay.top>", // 👈 已经替换为你的域名
            to: [email],
            subject: "您的 YL 账号验证码",
            html: `
              <div style="font-family: sans-serif; padding: 20px;">
                <h2>YL 账号中心</h2>
                <p>您的验证码是：</p>
                <h1 style="color: #3582e7; letter-spacing: 2px;">${code}</h1>
                <p>5 分钟内有效，请勿泄露给他人。</p>
              </div>
            `
          })
        });

        if (res.ok) {
          return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        } else {
          const err = await res.text();
          console.error("Resend Error:", err);
          return new Response(`邮件发送失败: ${err}`, { status: 500, headers: corsHeaders });
        }
      }

      // 2. 注册接口
      if (request.method === "POST" && url.pathname === "/api/register") {
        const { email, code, password } = await request.json();
        
        // 验证验证码
        const record = await env.DB.prepare("SELECT * FROM verify_codes WHERE email = ? AND code = ?").bind(email, code).first();
        if (!record) return new Response("验证码错误", { status: 400, headers: corsHeaders });
        if (new Date(record.expires_at) < new Date()) return new Response("验证码已过期", { status: 400, headers: corsHeaders });

        // 验证通过，注册用户
        const hash = await hashPassword(password);
        try {
          await env.DB.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").bind(email, hash).run();
          await env.DB.prepare("DELETE FROM verify_codes WHERE email = ?").bind(email).run(); // 用完销毁
          return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        } catch (e) {
          return new Response("该邮箱已注册", { status: 400, headers: corsHeaders });
        }
      }

      // 3. 登录接口
      if (request.method === "POST" && url.pathname === "/api/login") {
        const { email, password } = await request.json();
        const hash = await hashPassword(password);
        
        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ? AND password_hash = ?").bind(email, hash).first();
        if (user) {
          // 简单生成一个 Token (真实生产环境建议用 JWT)
          const token = btoa(email + ":" + Date.now()); 
          return new Response(JSON.stringify({ success: true, token, email }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        } else {
          return new Response("账号或密码错误", { status: 401, headers: corsHeaders });
        }
      }

      // 4. 重置密码接口
      if (request.method === "POST" && url.pathname === "/api/reset-password") {
        const { email, code, newPassword } = await request.json();
        
        const record = await env.DB.prepare("SELECT * FROM verify_codes WHERE email = ? AND code = ?").bind(email, code).first();
        if (!record || new Date(record.expires_at) < new Date()) return new Response("验证码错误或已过期", { status: 400, headers: corsHeaders });

        const hash = await hashPassword(newPassword);
        await env.DB.prepare("UPDATE users SET password_hash = ? WHERE email = ?").bind(hash, email).run();
        await env.DB.prepare("DELETE FROM verify_codes WHERE email = ?").bind(email).run();
        
        return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: corsHeaders });
    }
  }
};