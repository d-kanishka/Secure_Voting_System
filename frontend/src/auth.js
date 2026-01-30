// frontend/src/auth.js
// Manage temp_token (sessionStorage) and final access_token (localStorage)
export const saveToken = (token) => localStorage.setItem("access_token", token);
export const clearToken = () => localStorage.removeItem("access_token");
export const getToken = () => localStorage.getItem("access_token");

export const saveTempToken = (t) => sessionStorage.setItem("temp_token", t);
export const getTempToken = () => sessionStorage.getItem("temp_token");
export const clearTempToken = () => sessionStorage.removeItem("temp_token");

/**
 * decodedUser:
 * - Reads the JWT access token payload and returns a normalized object:
 *   { username, role, mfa }
 * - Works with tokens where identity is the "sub" claim (string) and role/mfa are additional claims.
 */
export const decodedUser = (token) => {
  const tok = token || getToken();
  if (!tok) return null;
  try {
    const parts = tok.split(".");
    if (parts.length < 2) return null;
    const payload = JSON.parse(atob(parts[1]));
    // Different libs place subject under 'sub' or 'identity' or 'username'
    const username = payload.sub || payload.identity || payload.username || null;
    const role = payload.role || null;
    const mfa = payload.mfa || false;
    return { username, role, mfa };
  } catch (e) {
    return null;
  }
};