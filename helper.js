// Developed by Halil Emre Yildiz (Github:@JahnStar)
export class Security{
  static escaped = {
    '"': '&quot;',
    "'": '&#39;',
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;'
  };
  
  static regex_html_characters_to_escape = /["'&<>]/g;
  
  static escapeHtml(html) {
    return String(html).replace(
      this.regex_html_characters_to_escape,
      match => this.escaped[match]
    );
  }

  // Account process
  static async hashPassword(password) {
    // Placeholder for hash function (you can implement your own hash function here)
    // As an example, let's assume a simple hashing algorithm (not secure)
    // Use "bcrypt" framework
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashedPassword;
  }
  
  static async comparePasswords(plaintext_psw, hashed_psw) {
    const hashedPlaintext = await this.hashPassword(plaintext_psw);
    return hashedPlaintext === hashed_psw;
  }

  static compareToken(current, compared) {
    return current === compared ? true : false;
  }

  // Token generator
  static async generateRandomToken(length = 48) {
    let uuid = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_';
    for (let i = 0; i < length; i++) uuid += chars[Math.floor(Math.random() * chars.length)];
    return uuid;
  }

  // Generate JSON Web Token 
  static async generateJWT(payload, secretKey) {
    // Encode Header
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header));
    // Encode Payload
    const encodedPayload = btoa(JSON.stringify(payload));
    // Encode Signature
    const signatureInput = encodedHeader + '.' + encodedPayload;
    const encoder = new TextEncoder();
    const signatureKey = await crypto.subtle.importKey('raw', encoder.encode(secretKey), { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', signatureKey, encoder.encode(signatureInput));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    // JWT
    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
  }

  // Parse JSON Web Token
  static async parseJWT(jwt, secretKey) {
    // Split JWT
    const [encodedHeader, encodedPayload, encodedSignature] = jwt.split('.');
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const signatureInput = encodedHeader + '.' + encodedPayload;		
    // Valid Signature
    const signatureKey = await crypto.subtle.importKey('raw', encoder.encode(secretKey), { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['verify'] );
    const signature = new Uint8Array(Array.from(atob(encodedSignature)).map(char => char.charCodeAt(0)));
    const isSignatureValid = await crypto.subtle.verify('HMAC', signatureKey, signature, encoder.encode(signatureInput));
    if (!isSignatureValid) throw new Error('JWT signature could not be verified!');
    // Decode Payload
    const decodedPayload = decoder.decode(new Uint8Array(Array.from(atob(encodedPayload)).map(char => char.charCodeAt(0))));
    return JSON.parse(decodedPayload);
  }
}

export class Examples {
  static page404(status=404){
    const html = `<!DOCTYPE html><title>404 Not Found</title><h1>404 Not Found</h1><script>setTimeout(() => { window.location.href = '/home'; }, 3000);</script>`;
    return new Response(html, { status: status, headers: { 'Content-Type': 'text/html' } });
  }
  static page401(status=401){
    const html = `<!DOCTYPE html><title>Unauthorized Access</title><h1>Unauthorized Access</h1><p>You are not authorized to access this resource.</p><script>setTimeout(() => { window.location.href = '/home'; }, 1000);</script>`;
    return new Response(html, { status: status, headers: { 'Content-Type': 'text/html' } });
  }
  static pageRedirect(url, img, delay, status=302, clean_cookies = false){
    const html = this.htmlGenerateCard(img, "Redirecting", `to ${url}...`, "Almost there, please wait a moment") + `<script>setTimeout(() => { window.location.href = '${url}'; }, ${delay});</script>`; 
    const response = new Response(html, { status:status, headers: { 'Content-Type': 'text/html' } });
    if (clean_cookies) {
      response.headers.set('Set-Cookie', 'session=null; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/');
      response.headers.set('Content-Type', 'text/plain');
    }
    return response;
  }
  // HTML
  static htmlGenerateCard(img, header, text, footer) {
    const blankImage = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxOTJweCIgaGVpZ2h0PSIxOTJweCIgdmlld0JveD0iMCAwIDE5MiAxOTIiPgogICAgPGcgZmlsbD0ibm9uZSI+CiAgICAgICAgPGcgZmlsbC1ydWxlPSJldmVub2RkIiBzdHJva2U9IiNmZmYiPgogICAgICAgICAgICA8cGF0aCBkPSJNMCAwaDE5MnB4MTkySDB6Ii8+CiAgICAgICAgPC9nPgogICAgPC9nPgogIDwvc3ZnPg==';

    return `
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss/dist/tailwind.min.css" rel="stylesheet"/>
        <div class="flex items-center justify-center min-h-screen bg-gray-100">
            <div class="flex flex-col items-center w-full max-w-xs p-4 bg-white rounded-3xl md:flex-row">
                <div class="-mt-28 md:-my-16 md:-ml-32" style="clip-path: url(#roundedPolygon)">
                    <img
                        class="w-auto h-48"
                        src="${blankImage}"
                        alt="${header}"
                        onload="this.src='${img}';"
                    />
                </div>
                <div class="flex flex-col space-y-4">
                    <div class="flex flex-col items-center md:items-start">
                        <h2 class="text-xl font-medium">${header}</h2>
                        <p class="text-base font-medium text-gray-400">${text}</p>
                    </div>
                    <div class="flex items-center justify-center space-x-3 md:justify-start">
                        <p class="text-xs font-medium">${footer}</p>
                    </div>
                </div>
            </div>
            <svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" >
                <defs>
                    <clipPath id="roundedPolygon">
                        <path d="M79 6.237604307034a32 32 0 0 1 32 0l52.870489570875 30.524791385932a32 32 0 0 1 16 27.712812921102l0 61.049582771864a32 32 0 0 1 -16 27.712812921102l-52.870489570875 30.524791385932a32 32 0 0 1 -32 0l-52.870489570875 -30.524791385932a32 32 0 0 1 -16 -27.712812921102l0 -61.049582771864a32 32 0 0 1 16 -27.712812921102"/>
                    </clipPath>
                </defs>
            </svg>
        </div>
    `;
  }  
}