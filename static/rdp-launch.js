async function launchRdp(target, password, newPassword) {
    const query = new URLSearchParams();
    if (target) query.set('connectTo', target);
    const headers = { 'X-Rustguac-Launch': '1' };
    const request = { method: 'POST', headers };
    if (password !== undefined) {
        headers['Content-Type'] = 'application/json';
        request.body = JSON.stringify({ password, new_password: newPassword });
    }
    const response = await fetch('/rdp/launch?' + query.toString(), request);
    const result = await response.text();
    if (!response.ok) {
        const error = new Error(result);
        error.prompt = response.headers.get('x-rustguac-prompt');
        throw error;
    }
    if (!result.startsWith('/client/')) throw new Error('Could not open the Remote Desktop session.');
    return result;
}
