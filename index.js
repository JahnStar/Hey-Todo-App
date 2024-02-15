import { Security } from './helper.js';
import login_page from './login.html';
import app_page from './app.html';

export default {
  async fetch(request, env) {
    if (request.method === 'POST') return await PageLoader.Init(request, env);

    const searchParams = (new URL(request.url)).searchParams;
    const get_token = searchParams.get('token');
    const get_key = searchParams.get('username');
    const get_logout_key = searchParams.get('logout');
    if (get_logout_key) await PageLoader.resetToken(env, get_logout_key);
    else if (get_key && get_token)
    {
      const cache = JSON.parse(await PageLoader.getCache(env, get_key));
      if (cache && cache.account.token === get_token) return TodoApp.loadPage(app_page, cache);
    }
    // Login page
    return TodoApp.loadPage(login_page);
  }
}; 

class PageLoader {
  static setCache = (env, key, data) => env.EXAMPLE_TODOS.put(key, data);
  static getCache = (env, key) => {
      const value = env.EXAMPLE_TODOS.get(key);
      return value !== undefined ? value : null;
  };
  static async resetToken(env, key){
    const cache = JSON.parse(await PageLoader.getCache(env, key));
    cache.account.token = Security.uuid();
    await PageLoader.setCache(env, key, JSON.stringify(cache));
    return cache;
  }

  static async Init(request, env) {
    let message = `Error: something is wrong.`;
    let status = 401;

    try {
      const client_data = await request.json();
      const process = Security.escapeHtml(client_data.process);
      const username = Security.escapeHtml(client_data.username);
      const password = Security.escapeHtml(client_data.password);
      
      if (username && username.trim() && password && password.trim()) {
        if (process === "signup") {
          const hashedPassword = await Security.hashPassword(password);
          const defaultData = { account: { username: username, password: hashedPassword, token: Security.uuid() }, data : {todos: [{ id: "1", name: "use a todo app", completed: true}]} };
          
          const cache = JSON.parse(await this.getCache(env, username));
          if (!cache) {
            await this.setCache(env, username, JSON.stringify(defaultData));
            message = `\nYour account has been successfully created!\n\nPlease, login to continue...`;
          } else {
            message = "You have already signed up!";
          }
        } else if (process === "login") {
          const cache = await this.resetToken(env, username);
          if (cache && (await Security.comparePasswords(password, cache.account.password))) {
            // Redirect new page with new token
            return new Response(JSON.stringify({ token: cache.account.token }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' }
            });
          } else {
            message = "Invalid username or password!";
            status = 401;
          }
        }
      } else {
        message = "Please provide both username and password!";
        status = 400;
      }
    } catch (error) {
      message = `Error: ${error.message}`;
      status = 500;
    }

    return new Response(JSON.stringify({ message: message }), {
      status: status,
      headers: { 'Content-Type': 'application/json' }
    });
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
    body = body.replace(/\$TITLE_USER/g, Security.escapeHtml(cache_data.account.username));

    return new Response(body, {
      headers: { 'Content-Type': 'text/html' }
    });
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