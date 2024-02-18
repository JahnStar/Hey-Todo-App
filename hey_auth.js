// Developed by Halil Emre Yildiz (Github:@JahnStar)
import { Security, Examples } from './helper.js';
export class SessionManager {
    // Requirements
    static Init(setFunction, getFunction) {
        this.setCache = setFunction;
        this.getCache = getFunction;
    };
    static setCache = (env, key, data) => env.environment_variable.put(key, data);
    static getCache = (env, key) => { try { return env.environment_variable.get(key); } catch { return null; } };
    //
    static async getUserID(email) { return await Security.hashPassword(email); }
    
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
    
    static async AuthResponse(env, response, client_auth, ip_address, login=false, logout=false){
      const auth_response = { 
        body: await response.text(),
        headers: response.headers ? response.headers : new Headers()
      }
      return await this.Auth(env, auth_response, client_auth, ip_address, login, logout); 
    }
  
    static async Auth(env, auth_response, client_auth, ip_address, login=false, logout=false){ 
      if (!client_auth) return Examples.pageRedirect('/home', 'https://github.com/jahnstar.png', 2000, true);
      // Get user
      const cache = JSON.parse(await this.getCache(env, client_auth.user_id));
      if (!cache) return Examples.page404();
      // Compare token 
      const access = Security.compareToken(cache.session.token, client_auth.session_token);
      // Reset token 
      const new_session_jwt = await this.GenerateSessionJWT(env, cache, client_auth.user_id, ip_address, login);
      // Set Client Cache
      let new_cookies = 'session=null; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly';
      // Auth & Sync
      if (access && !logout) new_cookies = `session=${new_session_jwt}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`;
      else auth_response.body = await Examples.pageRedirect('/home', 'https://github.com/jahnstar.png', 2000).text();
      auth_response.headers.append('Set-Cookie', new_cookies);
      return new Response(auth_response.body, { status: access ? 200 : 401, headers: auth_response.headers }); 
    }
  
    static async ParseSessionJWT(client_cache) { 
      const jwtToken = client_cache.split("session=")[1].split('?')[0];
      const decoded_authPayload = await Security.parseJWT(jwtToken, "Www.JahnStarGames.coM");
      return decoded_authPayload;
    }
    
    static async GenerateSessionJWT(env, cache, user_id, ip_address, logged_in = null){
      // Log
      cache.session.ip_address = ip_address;
      cache.session.last_tried = new Date().toISOString();
      if (logged_in) cache.session.last_login = new Date().toISOString();
      //
      const new_session_token = await Security.generateRandomToken();
      cache.session.token = new_session_token;
      await this.setCache(env, user_id, JSON.stringify(cache));
      // Generate JWT token
          const authPayload = { user_id:user_id, session_token: new_session_token };
      const jwtToken = await Security.generateJWT(authPayload, "Www.JahnStarGames.coM");
      return `${jwtToken}?`;
    }

    static async Register(env, username, email, password, form_status){
      let message = "Register error: Something went wrong.";
      let status = 403;
      try{
        if (form_status === 404) {
          if (!username) username = Security.generateRandomToken(16);
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