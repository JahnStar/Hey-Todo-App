
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
  
  static async comparePasswords(plaintextPassword, hashedPassword) {
    const hashedPlaintext = await this.hashPassword(plaintextPassword);
    return hashedPlaintext === hashedPassword;
  }

  // ID generator
  static uuid(){
    let uuid = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
    const charIndex = Math.floor(Math.random() * chars.length);
    uuid += chars[charIndex];
    if (i === 7 || i === 11 || i === 15 || i === 19) {
        uuid += '-';
    }
    }
    return uuid;
}
}