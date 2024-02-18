import { SessionManager as HeyAuth } from './hey_auth.js';
import { Security } from './helper.js';
import login_page from './login.html';
import app_page from './app.html';

export default {
  async fetch(request, env) {
    HeyAuth.Init((env, key, data) => env.EXAMPLE_TODOS.put(key, data), (env, key) => env.EXAMPLE_TODOS.get(key));
    //
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
        const auth_validity = await HeyAuth.AuthValidity(env, email, password);
        //
        if (process === 'login') {
          if (auth_validity.status == 200) return await HeyAuth.AuthResponse(env, Response.json({login:"Successfully." }), auth_validity.payload, request.headers.get('CF-Connecting-IP'));
          else if (auth_validity.status == 401) return new Response(JSON.stringify({message:`Login error: Incorrect email or password. (code:${auth_validity.status})`}), {status:401});
          else return new Response(JSON.stringify({message:`Login error: Account not found. (code:${auth_validity.status})`}), {status:auth_validity.status});
        }
        else if (process === 'signup') return await HeyAuth.Register(env, username, email, password, auth_validity.status);
        else new Response(JSON.stringify({message:`Bad request: Invalid formdata. (code:${400})`}), {status:400});
        return Response.json({message:`Form Error: Access denied. (code:${auth_validity.status})`});
      }
    }
    if (cookies)
    {
      const client_payload = await HeyAuth.ParseSessionJWT(cookies);
      const logout = (new URL(request.url)).pathname == '/logout';
      const ip_address = request.headers.get('CF-Connecting-IP');
      //
      if (request.method === 'GET') {
        const requested_response = await TodoApp.loadPage(app_page, JSON.parse(await HeyAuth.getCache(env, client_payload.user_id)));
        return  await HeyAuth.AuthResponse(env, requested_response, client_payload, ip_address, logout);
      }
      // let requested_callback;
      // else if (request.method === 'PUT') {
      //   requested_callback = async (headers) => {
      //     const request_json = await request.json();
      //     if (request_json.data)
      //     {
      //       const cache = JSON.parse(await HeyAuth.getCache(env, client_payload.user_id));
      //       cache.data = JSON.stringify(request_json.data);
      //       await HeyAuth.setCache(env, client_payload.user_id, JSON.stringify(cache));
      //       requested_response = new Response(JSON.stringify({message:"Saved successfully!"}), {status: 200, headers:headers});
      //     }
      //   }
      // }
      // const authed = await HeyAuth.AuthResponse(env, requested_response, client_payload, request.headers.get('CF-Connecting-IP'), logout);
      // if (authed.status == 200) {
      //   if (requested_callback){
      //     await requested_callback(authed.headers);
      //     if (requested_response) return requested_response;
      //   }
      // }
      // return authed;
    }
    return TodoApp.loadPage(login_page);
  }
}; 

class TodoApp {
  static async loadPage(html, cache_data = null) {
    if (!cache_data) return new Response(html, { headers: { 'Content-Type': 'text/html' } });
    const todos = JSON.parse(cache_data.data).todos;
    let body = html.replace(
      '$TODOS',
      JSON.stringify(
        todos?.map(todo => ({
          id: Security.escapeHtml(todo.id),
          name: Security.escapeHtml(todo.name),
          completed: !!todo.completed
        })) ?? []
      )
    );
    body = body.replace(/\$TITLE_USER/g, Security.escapeHtml(cache_data.account.username));

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