import { Security, Examples } from './helper.js';
import login_page from './login.html';
import app_page from './app.html';

export default {
  async fetch(request, env) {
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
        const auth_validity = await SessionManager.AuthValidity(env, email, password);
        //
        if (process === 'login') {
          if (auth_validity.status == 200) return await SessionManager.Auth(env, Response.json({login:"Successfully." }), auth_validity.auth, request.headers.get('CF-Connecting-IP'), true);
          else if (auth_validity.status == 401) return new Response(JSON.stringify({message:`Login error: Incorrect email or password. (code:${auth_validity.status})`}), {status:401});
          else return new Response(JSON.stringify({message:`Login error: Account not found. (code:${auth_validity.status})`}), {status:auth_validity.status});
        }
        else if (process === 'signup') return await SessionManager.Register(env, username, email, password, auth_validity.status);
        else new Response(JSON.stringify({message:`Bad request: Invalid formdata. (code:${400})`}), {status:400});
        return Response.json({message:`Form Error: Access denied. (code:${auth_validity.status})`});
      }
    }
    if (cookies)
    {
      const logout = (new URL(request.url)).pathname == '/logout'; 
      const auth = SessionManager.ParseSession(cookies);
      const response = await TodoApp.loadPage(app_page);
      return await SessionManager.Auth(env, SessionManager.AuthResponse((await response.text()),response.headers), auth, request.headers.get('CF-Connecting-IP'), false, logout); 
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

  static async AuthValidity(env, email, password, if_its_new_session=false) {
    let status = 401;
    const auth = { user_id : await this.getUserID(email) }
    try{
      if (email && email.trim() && password && password.trim()){
        const cache = JSON.parse(await this.getCache(env, auth.user_id));
        if (cache) {
          if (await Security.comparePasswords(password, cache.account.password)) {
            status = !if_its_new_session || !cache.session.token ? 200 : 409;
            auth.session_token = cache.session.token;
          }
          else status = 401;
        } else status = 404;
      } else status = 400;
    } catch(error) { 
      // throw new Error(error); 
      status = 500;
    }
    return { auth: auth, status: status };
  }
 
  static async Auth(env, auth_response, client_auth, ip_address, login=false, logout=false){ 
    if (!client_auth) return Examples.pageRedirect('/home', 'https://github.com/jahnstar.png', 2000, true);
    // Get user
    const cache = JSON.parse(await this.getCache(env, client_auth.user_id));
    if (!cache) return Examples.page404();
    // Compare token 
    const access = Security.compareToken(cache.session.token, client_auth.session_token);
    // Reset token 
    const new_session = await this.GenerateSession(env, cache, client_auth.user_id, ip_address, login);
    // Set Client Cache
    let new_cookies = 'session=null; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly';
    // Auth & Sync
    if (access && !logout) new_cookies = `session=${new_session}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`;
    else auth_response.body = await Examples.pageRedirect('/home', 'https://github.com/jahnstar.png', 2000).text();
    auth_response.headers.append('Set-Cookie', new_cookies);
    return new Response(auth_response.body, { status: auth_response.status, headers: auth_response.headers }); 
  }

  static ParseSession(client_cache) { 
    let auth = null;
    try { 
      const client_session = client_cache.split("session=")[1].split('.')[0];
      auth = {
        user_id: client_session.split(':')[0],
        session_token: client_session.split(':')[1]
      };
    }
    catch (error) { 
      // throw Error(error);
    }
    return auth;
  }

  static async GenerateSession(env, cache, user_id, ip_address, logged_in = null){
    // Log
    cache.session.ip_address = ip_address;
    cache.session.last_tried = new Date().toISOString();
    if (logged_in) cache.session.last_login = new Date().toISOString();
    //
    const new_session_token = await Security.generateJWT();
    cache.session.token = new_session_token;
    await this.setCache(env, user_id, JSON.stringify(cache));
    return `${user_id}:${new_session_token}.`;
  }

  static async Register(env, username, email, password, form_status){
    let message = "Register error: Something went wrong.";
    let status = 403;
    try{
      if (form_status === 404) {
        if (!username) username = Security.uuid().substring(4, 16);
        const user_id = await this.getUserID(email);
        const hashedPassword = await Security.hashPassword(password);
        const new_user_data = { account: { username: username, email: email, password: hashedPassword }, session: { ip_address: "no_login", last_tried:"", last_login: "", created: new Date().toISOString(), token: "+" }, data : { todos: [{ id: "1", name: "use a todo app", completed: true}] } };
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