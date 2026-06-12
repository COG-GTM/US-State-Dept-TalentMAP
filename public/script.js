// API root is configurable at deploy time via a global; defaults to a relative path
// so the middle-tier proxy can route the request to the API.
var TOKEN_URL = (window.TM_API_ROOT || '/api/v1') + '/accounts/token/';

function login(username, password) {
  return fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'username=' + encodeURIComponent(username) +
      '&password=' + encodeURIComponent(password),
  })
    .then(function handleResponse(response) {
      if (!response.ok) { throw new Error('Request failed'); }
      return response.json();
    })
    .then(function handleToken(data) {
      // POST the token to the middle tier, which stores it in an httpOnly
      // cookie and redirects. The token is never placed in the URL.
      var form = document.createElement('form');
      form.method = 'POST';
      form.action = '/talentmap/tokenValidation';
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'token';
      input.value = data.token;
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    })
    .catch(function handleError() {
      alert('Request failed');
    });
}

document.addEventListener('DOMContentLoaded', function init() {
  var form = document.getElementById('login-form');
  if (form) {
    form.addEventListener('submit', function onSubmit(event) {
      event.preventDefault();
      login(form.username.value, form.password.value);
    });
  }
});
