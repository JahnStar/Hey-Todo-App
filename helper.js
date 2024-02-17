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

  // Random ID generator
  static uuid(){
    let uuid = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
    const charIndex = Math.floor(Math.random() * chars.length);
    uuid += chars[charIndex];
    if (i === 7 || i === 11 || i === 15 || i === 19) uuid += '-';
    }
    return uuid;
  }

  // JSON Web Token generator
  static async generateJWT() {
    let uuid = '';
    const chars = '_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
    const charIndex = Math.floor(Math.random() * chars.length);
    uuid += chars[charIndex];
    if (i === 7 || i === 11 || i === 15 || i === 19) uuid += '-';
    }
    return uuid;
  }
}

export class Examples {
  static page404(){
    const html = `<!DOCTYPE html><title>404 Not Found</title><h1>404 Not Found</h1><script>setTimeout(() => { window.location.href = '/home'; }, 3000);</script>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
  }
  static page401(){
    const html = `<!DOCTYPE html><title>Unauthorized Access</title><h1>Unauthorized Access</h1><p>You are not authorized to access this resource.</p><script>setTimeout(() => { window.location.href = '/home'; }, 1000);</script>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
  }
  static pageRedirect(url, img, delay){
    const html =  this.htmlGenerateCard(img, "Redirecting", `to ${url}...`, "Almost there, please wait a moment") + `<script>setTimeout(() => { window.location.href = '${url}'; }, ${delay});</script>`; 
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
  }
  // HTML
  static htmlGenerateCard(img, header, text, footer) {
    return `
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss/dist/tailwind.min.css" rel="stylesheet"/>
        <div class="flex items-center justify-center min-h-screen bg-gray-100">
            <div class="flex flex-col items-center w-full max-w-xs p-4 bg-white rounded-3xl md:flex-row">
                <div class="-mt-28 md:-my-16 md:-ml-32" style="clip-path: url(#roundedPolygon)">
                    <img
                        class="w-auto h-48"
                        src="${img}"
                        alt="${header}"
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
            <svg width="0" height="0" xmlns="http://www.w3.org/2000/svg">
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