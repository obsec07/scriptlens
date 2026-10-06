const api = axios.create({baseURL: '/api/v2'});
api.post('/users', {email: user.email, role: 'member'}, {
  headers: {'X-CSRF-Token': csrfToken}
});
fetch(`/api/orders/${orderId}`, {credentials: 'include'});
const payload = location.hash.slice(1);
document.querySelector('#preview').innerHTML = payload;
fetch('/graphql', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    query: 'query Order($id: ID!) { order(id: $id) { id total } }',
    variables: {id: orderId}
  })
});
