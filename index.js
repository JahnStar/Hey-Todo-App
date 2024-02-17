import { Security, Examples } from './helper.js';
import login_page from './login.html';
import app_page from './app.html';

export default {
  async fetch(request, env) {
    if ((new URL(request.url)).searchParams.get('developermode')) return new Response(`<!DOCTYPE html><h1>${await SessionManager.GetBearer(env, 'johndoe@mail.comA1', 'johndoe@mail.comA1')}</h1><button style="width: 25%; padding-top: 25%" onclick="window.location.href = '/?developermode=on';"></button>`, { status: 200, headers: { 'Content-Type': 'text/html'} })
    const cookies = request.headers.get('Cookie');
    //
    if (request.method === 'POST') {
      const contentType = request.headers.get('Content-Type');
      //  
      if (contentType && (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')))
      {
        const formData = await request.formData();
        const process =  Security.escapeHtml(formData.get('process'));
        const username = Security.escapeHtml(formData.get('username'));
        const email = Security.escapeHtml(formData.get('email'));
        const password = Security.escapeHtml(formData.get('password'));
        //
        let form_status = await SessionManager.FormValidity(env, email, password);
        //
        if (process === 'login') {
          if (form_status == 200) {
            const bearer = await SessionManager.GetBearer(env, email, password); 
            if (bearer) return await SessionManager.BearerAuth(env, Response.json({login:"Successfully."}), bearer, true);
            else form_status = 401;
          }
          else return new Response(JSON.stringify({message:`Login error: Account not found. (code:${form_status})`}), {status:404});
        }
        else if (process === 'signup') return await SessionManager.Register(env, username, email, password, form_status);
        else form_status = 400;
        return Response.json({message:`Form Error: Access denied. (code:${form_status})`}); 
      }
    }
    if (cookies)
    {
      const logout = (new URL(request.url)).pathname == '/logout'; 
      const bearer = await SessionManager.CookiesBearer(cookies);
      const response = await TodoApp.loadPage(app_page);
      return await SessionManager.BearerAuth(env, SessionManager.AuthResponse(await response.text(),response.headers), bearer, false, logout); 
    }
    return TodoApp.loadPage(login_page);
  }
}; 

class SessionManager {
  static setCache = (env, key, data) => env.EXAMPLE_TODOS.put(key, data);
  static getCache = (env, key) => {
      try { return env.EXAMPLE_TODOS.get(key); }
      catch { return null; }
  };

  static async getUserID(email) {
    return await Security.hashPassword(email);
  }

  static AuthResponse(body, headers, status = 200){
    return { 
      body: body,
      status: status,
      headers: headers ? headers : new Headers()
    };
  }

  static CookiesBearer = (cookies) => {    
    try { 
      return cookies.split("session_token=")[1].split('.')[0]; }
    catch { return null; }
  }

  static ToBearer(user_id, session_token){
    return `Bearer ${user_id}:${session_token}.`;
  }

  static async GetBearer(env, email, password){
    if (!email || !email.trim() || !password || !password.trim()) return null;
    const auth = { user_id: await this.getUserID(email) }
    // Get user
    const cache = JSON.parse(await this.getCache(env, auth.user_id));
    if (!cache) return false;
    // Compare passwords
    if (!Security.comparePasswords(cache.account.password, password)) return null;
    //
    auth.session_token = cache.session.token;
    if (!auth.session_token) return false;
    return this.ToBearer(auth.user_id, auth.session_token);
  }
  
  static async BearerAuth(env, auth_response, cookies_bearer, login=false, logout=false){ 
    if (!cookies_bearer) return Examples.page404();
    const cookies_auth = {
      user_id: cookies_bearer.substring(7).split(':')[0],
      session_token: cookies_bearer.split(':')[1].split('.')[0]
    }
    // Get user
    const cache = JSON.parse(await this.getCache(env, cookies_auth.user_id));
    if (!cache) return Examples.page404();
    // Compare token 
    const access = Security.compareToken(cache.session.token, cookies_auth.session_token);
    // Reset token 
    if ((login || access) && !logout) {
      const session_token = await this.ResetToken(env, cache, cookies_auth.user_id);
      cookies_bearer = this.ToBearer(cookies_auth.user_id, session_token);
      // Set Cookies
      auth_response.headers.append('Set-Cookie', `session_token=${cookies_bearer}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
    }
    else {
      await this.ResetToken(env, cache, cookies_auth.user_id);
      auth_response.body = await Examples.pageRedirect('/home', 'https://github.com/jahnstar.png', 1500).text();
      // Set Cookies
      auth_response.headers.append('Set-Cookie', 'session_token=delete; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly');
    }
    return new Response(auth_response.body, { status: auth_response.status, headers: auth_response.headers }); 
  }

  static async ResetToken(env, cache, user_id){
    if (!user_id) return null;
    const new_session_token = await Security.generateJWT();
    cache.session.token = new_session_token;
    await this.setCache(env, user_id, JSON.stringify(cache));
    return new_session_token;
  }

  static async FormValidity(env, email, password, if_its_new_session=false) {
    try{
      if (email && email.trim() && password && password.trim()){
        const user_id = await this.getUserID(email);
        const cache = JSON.parse(await this.getCache(env, user_id));
        if (cache) {
          if (Security.comparePasswords(password, cache.account.password)) return !if_its_new_session || !cache.session.token ? 200 : 409;
          else 401;
        } else return 404;
      } else return 400;
    } catch(error) { 
      // throw new Error(error); 
      return 500;
    } 
  }

  static async Register(env, username, email, password, form_status){
    let message = "Register error: Something went wrong.";
    let status = 403;
    try{
      if (form_status === 404) {
        if (!username) username = Security.uuid().substring(4, 16);
        const user_id = await this.getUserID(email);
        const hashedPassword = await Security.hashPassword(password);
        const new_user_data = { account: { username: username, email: email, password: hashedPassword }, session: { token: "+" }, data : { todos: [{ id: "1", name: "use a todo app", completed: true}] } };
        try{
          await this.setCache(env, user_id, JSON.stringify(new_user_data));
          message = "Account created!"
          status = 200;
        }
        catch {
          message = "Register error: Service is unavailable.";
          status = 503;
        }
      }
      else {
        message = "Account is already registered."
        status = 409;
      }
    }
    catch { status = 500; }
    return new Response(JSON.stringify({message:message + ` (code:${status})`}), { status: status, headers: { 'Content-Type': 'application/json' } });
  }
}

class TodoApp {
  static async loadPage(html, cache_data = null) {
    if (!cache_data) return new Response(html, { headers: { 'Content-Type': 'text/html' } });

    let body = html.replace(
      '$TODOS',
      JSON.stringify(
        cache_data.data.todos?.map(todo => ({
          id: Security.escapeHtml(todo.id),
          name: Security.escapeHtml(todo.name),
          completed: !!todo.completed
        })) ?? []
      )
    );
    body = body.replace(/\$TITLE_USER/g, Security.escapeHtml(cache_data.account.email));

    return new Response(body, { headers: { 'Content-Type': 'text/html' }});
  }

  static async updateCache(request, env, cacheKey) {
    const body = await request.text();
    try {
      JSON.parse(body);
      await env.EXAMPLE_TODOS.put(cacheKey, body);
      return new Response(body, { status: 200 });
    } catch (err) {
      return new Response(err, { status: 500 });
    }
  }
}